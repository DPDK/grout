// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Christophe Fontaine
// Copyright (c) 2023 Robin Jarry

#include "bro.h"
#include "control.h"
#include "dpdk.h"
#include "rte_mempool.h"
#include "signals.h"

#include <bro_api.h>

#include <event2/event.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>

#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void usage(const char *prog) {
	printf("Usage: %s [-t] [-c FILE] [-s PATH]\n", prog);
	puts("");
	puts("  Boring router.");
	puts("");
	puts("options:");
	puts("  -t, --test-mode            Run in test mode (no hugepages).");
	puts("  -c FILE, --config FILE     Path the configuration file.");
	puts("  -s PATH, --socket PATH     Path the control plane API socket.");
}

struct brouter bro;

static int parse_args(int argc, char **argv) {
	int c;

	bro.api_sock_path = DEFAULT_SOCK_PATH;

#define FLAGS "c:s:ht"
	static struct option long_options[] = {
		{"socket", required_argument, NULL, 's'},
		{"config", required_argument, NULL, 'c'},
		{"help", no_argument, NULL, 'h'},
		{"test-mode", no_argument, NULL, 't'},
		{0},
	};

	while ((c = getopt_long(argc, argv, FLAGS, long_options, NULL)) != -1) {
		switch (c) {
		case 's':
			bro.api_sock_path = optarg;
			break;
		case 'c':
			bro.config_file_path = optarg;
			break;
		case 't':
			bro.test_mode = true;
			break;
		case 'h':
			usage(argv[0]);
			return -1;
		default:
			goto end;
		}
	}
end:
	if (optind < argc) {
		fputs("error: invalid arguments", stderr);
		return -1;
	}

	return 0;
}

static int parse_config_file(void) {
	return 0;
}

static void event_fd_close(struct event *ev, void *priv) {
	(void)priv;
	close(event_get_fd(ev));
}

static void api_write_cb(evutil_socket_t sock, short what, void *buf) {
	struct event *ev = event_base_get_running_event(bro.base);
	struct bro_api_header *header = buf;
	ssize_t len;

	(void)what;

	len = sizeof(*header) + header->payload_len;

	if (send(sock, buf, len, MSG_DONTWAIT | MSG_TRUNC) < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto retry;
		LOG(ERR, "api_write_cb: %s", strerror(errno));
	}
	goto free;

retry:
	if (ev == NULL || event_add(ev, NULL) < 0) {
		LOG(ERR, "api_write_cb: failed to add event to loop");
		goto free;
	}
	return;

free:
	if (ev != NULL)
		event_free(ev);
	rte_mempool_put(bro.api_pool, buf);
}

static void api_read_cb(evutil_socket_t sock, short what, void *ctx) {
	struct event *ev = event_base_get_running_event(bro.base);
	struct event *write_ev;
	ssize_t len, resp_len;
	void *buf;

	(void)what;
	(void)ctx;

	if (rte_mempool_get(bro.api_pool, &buf) < 0) {
		LOG(ERR, "api_read_cb: no memory buffer available");
		return;
	}

	if ((len = recv(sock, buf, BRO_API_BUF_SIZE, MSG_DONTWAIT | MSG_TRUNC)) < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			rte_mempool_put(bro.api_pool, buf);
			return;
		}
		LOG(ERR, "api_read_cb: recv: %s", strerror(errno));
		goto close;
	} else if (len > (ssize_t)BRO_API_BUF_SIZE) {
		LOG(ERR, "api_read_cb: recv: request truncated");
		goto close;
	} else if (len == 0) {
		LOG(DEBUG, "api_read_cb: client disconnected");
		goto close;
	}

	struct bro_api_header *header = (struct bro_api_header *)buf;

	LOG(DEBUG, "api_read_cb: type=%u len=%u", header->type, header->payload_len);

	if (header->version != BRO_API_VERSION) {
		header->status = EPROTO;
		header->payload_len = 0;
		goto send;
	}

	ctrl_handler_t *handler = lookup_control_handler(header->type);
	if (handler == NULL) {
		header->status = ENOTSUP;
		header->payload_len = 0;
		goto send;
	}

	header->status = handler(header, header + 1);

send:
	resp_len = sizeof(*header) + header->payload_len;
	if (send(sock, buf, resp_len, MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto retry_send;
		LOG(ERR, "api_read_cb: send: %s", strerror(errno));
		goto close;
	}
	rte_mempool_put(bro.api_pool, buf);
	return;

retry_send:
	write_ev = event_new(bro.base, sock, EV_WRITE, api_write_cb, buf);
	if (write_ev == NULL || event_add(write_ev, NULL) < 0) {
		LOG(ERR, "api_write_cb: failed to add event to loop");
		if (write_ev != NULL)
			event_free(write_ev);
	}
	return;

close:
	rte_mempool_put(bro.api_pool, buf);
	if (ev != NULL)
		event_free_finalize(0, ev, event_fd_close);
}

static void listen_cb(evutil_socket_t sock, short what, void *ctx) {
	struct event *ev;
	int fd;

	(void)what;
	(void)ctx;

	if ((fd = accept4(sock, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			LOG(ERR, "accept: %s", strerror(errno));
		}
		return;
	}

	LOG(DEBUG, "new connection");

	ev = event_new(bro.base, fd, EV_READ | EV_PERSIST, api_read_cb, NULL);
	if (ev == NULL || event_add(ev, NULL) < 0) {
		LOG(ERR, "failed to add event to loop");
		if (ev != NULL)
			event_free(ev);
		close(fd);
	}
}

#define BACKLOG 16

static int listen_api_socket(void) {
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	int fd;

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		LOG(ERR, "socket: %s", strerror(errno));
		return -1;
	}

	strncpy(addr.sun_path, bro.api_sock_path, sizeof addr.sun_path - 1);

	if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		LOG(ERR, "bind: %s: %s", bro.api_sock_path, strerror(errno));
		close(fd);
		return -1;
	}

	if (listen(fd, BACKLOG) < 0) {
		LOG(ERR, "listen: %s: %s", bro.api_sock_path, strerror(errno));
		close(fd);
		return -1;
	}

	bro.ev_listen = event_new(bro.base, fd, EV_READ | EV_WRITE | EV_PERSIST, listen_cb, NULL);
	if (bro.ev_listen == NULL || event_add(bro.ev_listen, NULL) < 0) {
		close(fd);
		abort();
		return -1;
	}

	LOG(INFO, "listening on API socket %s", bro.api_sock_path);

	return 0;
}

int main(int argc, char **argv) {
	int ret = EXIT_FAILURE;

	if (parse_args(argc, argv) < 0)
		goto end;

	if (parse_config_file() < 0)
		goto end;

	if (dpdk_init(&bro) < 0)
		goto end;

	if ((bro.base = event_base_new()) == NULL) {
		LOG(ERR, "event_base_new: %s", strerror(errno));
		goto end;
	}

	if (listen_api_socket() < 0)
		goto end;

	if (register_signals(&bro) < 0)
		goto end;

	// run until signal or fatal error
	if (event_base_dispatch(bro.base) == 0)
		ret = EXIT_SUCCESS;

end:
	unregister_signals(&bro);
	if (bro.ev_listen) {
		close(event_get_fd(bro.ev_listen));
		event_free(bro.ev_listen);
	}
	if (bro.base)
		event_base_free(bro.base);
	unlink(bro.api_sock_path);
	libevent_global_shutdown();
	dpdk_fini(&bro);

	return ret;
}
