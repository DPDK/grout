// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Christophe Fontaine
// Copyright (c) 2023 Robin Jarry

#include "br.h"
#include "control-priv.h"
#include "dpdk.h"
#include "signals.h"

#include <br_api.h>
#include <br_api.pb-c.h>

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

struct boring_router br;

static int parse_args(int argc, char **argv) {
	int c;

	br.api_sock_path = DEFAULT_SOCK_PATH;

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
			br.api_sock_path = optarg;
			break;
		case 'c':
			br.config_file_path = optarg;
			break;
		case 't':
			br.test_mode = true;
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

static ssize_t send_response(evutil_socket_t sock, const Br__Response *resp) {
	uint8_t buf[BR_MAX_MSG_LEN];
	size_t len;

	if (resp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	LOG(DEBUG,
	    "for_id=%lu len=%lu data=%p status=%u %s",
	    resp->for_id,
	    resp->payload.len,
	    resp->payload.data,
	    resp->status,
	    strerror(resp->status));

	len = br__response__get_packed_size(resp);
	if (len > sizeof(buf)) {
		errno = ENOBUFS;
		return -1;
	}
	br__response__pack(resp, buf);

	return send(sock, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static void api_write_cb(evutil_socket_t sock, short what, void *priv) {
	struct event *ev = event_base_get_running_event(br.base);
	Br__Response *resp = priv;

	(void)what;

	if (send_response(sock, resp) < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto retry;
		LOG(ERR, "send_response: %s", strerror(errno));
	}
	goto free;

retry:
	if (ev == NULL || event_add(ev, NULL) < 0) {
		LOG(ERR, "failed to add event to loop");
		goto free;
	}
	return;

free:
	if (ev != NULL)
		event_free(ev);
	br__response__free_unpacked(resp, BR_PROTO_ALLOCATOR);
}

static void api_read_cb(evutil_socket_t sock, short what, void *priv) {
	struct event *ev = event_base_get_running_event(br.base);
	uint8_t buf[BR_MAX_MSG_LEN];
	Br__Response *resp = NULL;
	uint16_t service, method;
	struct event *write_ev;
	ssize_t len;

	(void)what;
	(void)priv;

	if ((len = recv(sock, buf, sizeof(buf), MSG_DONTWAIT | MSG_TRUNC)) < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		LOG(ERR, "recv: %s", strerror(errno));
		goto close;
	} else if (len > (ssize_t)sizeof(buf)) {
		LOG(ERR, "recv: request truncated");
		goto close;
	} else if (len == 0) {
		LOG(DEBUG, "client disconnected");
		goto close;
	}

	Br__Request *req = br__request__unpack(BR_PROTO_ALLOCATOR, len, buf);
	if (req == NULL) {
		LOG(ERR, "br__request__unpack: failed");
		goto close;
	}

	service = UINT16_C(req->service_method >> 16);
	method = UINT16_C(req->service_method);

	LOG(DEBUG, "id=%lu service=0x%x method=%u", req->id, service, method);
	br_service_handler_t *handler = br_lookup_service_handler(service);
	if (handler == NULL) {
		resp = br_new_response(req, ENOTSUP, 0, NULL);
		goto send;
	}

	resp = handler(req);

send:
	br__request__free_unpacked(req, BR_PROTO_ALLOCATOR);
	if (send_response(sock, resp) < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto retry_send;
		LOG(ERR, "send_response: %s", strerror(errno));
		goto close;
	}
	br__response__free_unpacked(resp, BR_PROTO_ALLOCATOR);
	return;

retry_send:
	write_ev = event_new(br.base, sock, EV_WRITE, api_write_cb, resp);
	if (write_ev == NULL || event_add(write_ev, NULL) < 0) {
		LOG(ERR, "failed to add event to loop");
		if (write_ev != NULL)
			event_free(write_ev);
		goto close;
	}
	return;

close:
	br__response__free_unpacked(resp, BR_PROTO_ALLOCATOR);
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

	ev = event_new(br.base, fd, EV_READ | EV_PERSIST, api_read_cb, NULL);
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

	strncpy(addr.sun_path, br.api_sock_path, sizeof addr.sun_path - 1);

	if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		LOG(ERR, "bind: %s: %s", br.api_sock_path, strerror(errno));
		close(fd);
		return -1;
	}

	if (listen(fd, BACKLOG) < 0) {
		LOG(ERR, "listen: %s: %s", br.api_sock_path, strerror(errno));
		close(fd);
		return -1;
	}

	br.ev_listen = event_new(br.base, fd, EV_READ | EV_WRITE | EV_PERSIST, listen_cb, NULL);
	if (br.ev_listen == NULL || event_add(br.ev_listen, NULL) < 0) {
		close(fd);
		abort();
		return -1;
	}

	LOG(INFO, "listening on API socket %s", br.api_sock_path);

	return 0;
}

int main(int argc, char **argv) {
	int ret = EXIT_FAILURE;

	if (parse_args(argc, argv) < 0)
		goto end;

	if (parse_config_file() < 0)
		goto end;

	if (dpdk_init(&br) < 0)
		goto end;

	if ((br.base = event_base_new()) == NULL) {
		LOG(ERR, "event_base_new: %s", strerror(errno));
		goto end;
	}

	if (listen_api_socket() < 0)
		goto end;

	if (register_signals(&br) < 0)
		goto end;

	// run until signal or fatal error
	if (event_base_dispatch(br.base) == 0)
		ret = EXIT_SUCCESS;

end:
	unregister_signals(&br);
	if (br.ev_listen) {
		close(event_get_fd(br.ev_listen));
		event_free(br.ev_listen);
	}
	if (br.base)
		event_base_free(br.base);
	unlink(br.api_sock_path);
	libevent_global_shutdown();
	dpdk_fini();

	return ret;
}
