// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br.h"
#include "control.h"
#include "dpdk.h"
#include "signals.h"

#include <br_api.h>
#include <br_control.h>
#include <br_log.h>

#include <event2/event.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_mempool.h>

#include <fcntl.h>
#include <getopt.h>
#include <sched.h>
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
	printf("Usage: %s [-h] [-v] [-t] [-c FILE] [-s PATH]\n", prog);
	puts("");
	puts("  Boring router.");
	puts("");
	puts("options:");
	puts("  -h, --help                 Display this help message and exit.");
	puts("  -v, --verbose              Increase verbosity.");
	puts("  -t, --test-mode            Run in test mode (no hugepages).");
	puts("  -s PATH, --socket PATH     Path the control plane API socket.");
	puts("                             Default: BR_SOCK_PATH from env or");
	printf("                             %s).\n", BR_DEFAULT_SOCK_PATH);
}

static struct boring_router br;
static struct event_base *ev_base;

static int parse_args(int argc, char **argv) {
	int c;

#define FLAGS ":s:htv"
	static struct option long_options[] = {
		{"socket", required_argument, NULL, 's'},
		{"help", no_argument, NULL, 'h'},
		{"test-mode", no_argument, NULL, 't'},
		{"verbose", no_argument, NULL, 'v'},
		{0},
	};

	opterr = 0; // disable getopt default error reporting

	br.api_sock_path = getenv("BR_SOCK_PATH");
	br.log_level = RTE_LOG_NOTICE;

	while ((c = getopt_long(argc, argv, FLAGS, long_options, NULL)) != -1) {
		switch (c) {
		case 's':
			br.api_sock_path = optarg;
			break;
		case 't':
			br.test_mode = true;
			break;
		case 'v':
			br.log_level++;
			break;
		case 'h':
			usage(argv[0]);
			return -1;
		case ':':
			usage(argv[0]);
			fprintf(stderr, "error: -%c requires a value", optopt);
			return -1;
		case '?':
			usage(argv[0]);
			fprintf(stderr, "error: -%c unknown option", optopt);
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

	if (br.api_sock_path == NULL)
		br.api_sock_path = BR_DEFAULT_SOCK_PATH;

	return 0;
}

static void finalize_close_fd(struct event *ev, void *priv) {
	(void)priv;
	close(event_get_fd(ev));
}

static ssize_t send_response(evutil_socket_t sock, struct br_api_response *resp) {
	if (resp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	LOG(DEBUG,
	    "for_id=%u len=%u status=%u %s",
	    resp->for_id,
	    resp->payload_len,
	    resp->status,
	    strerror(resp->status));

	size_t len = sizeof(*resp) + resp->payload_len;
	return send(sock, resp, len, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static void api_write_cb(evutil_socket_t sock, short what, void *priv) {
	struct event *ev = event_base_get_running_event(ev_base);
	struct br_api_response *resp = priv;

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
	free(resp);
	if (ev != NULL)
		event_free(ev);
}

static void api_read_cb(evutil_socket_t sock, short what, void *ctx) {
	struct event *ev = event_base_get_running_event(ev_base);
	void *req_payload = NULL, *resp_payload = NULL;
	struct br_api_response *resp = NULL;
	struct br_api_request req;
	struct event *write_ev;
	struct api_out out;
	ssize_t len;

	(void)ctx;

	if (what & EV_CLOSED)
		goto close;

	if ((len = recv(sock, &req, sizeof(req), MSG_DONTWAIT)) < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		LOG(ERR, "recv: %s", strerror(errno));
		goto close;
	} else if (len == 0) {
		LOG(DEBUG, "client disconnected");
		goto close;
	}

	if (req.payload_len > 0) {
		req_payload = malloc(req.payload_len);
		if (req_payload == NULL) {
			LOG(ERR, "cannot allocate %u bytes for request payload", req.payload_len);
			goto close;
		}
		if ((len = recv(sock, req_payload, req.payload_len, MSG_DONTWAIT)) < 0) {
			LOG(ERR, "recv: %s", strerror(errno));
			goto close;
		} else if (len == 0) {
			LOG(DEBUG, "client disconnected");
			goto close;
		}
	}

	const struct br_api_handler *handler = lookup_api_handler(&req);
	if (handler == NULL) {
		out.status = ENOTSUP;
		out.len = 0;
		goto send;
	}

	LOG(DEBUG,
	    "request: id=%u type=0x%08x '%s' len=%u",
	    req.id,
	    req.type,
	    handler->name,
	    req.payload_len);

	out = handler->callback(req_payload, &resp_payload);

send:
	resp = malloc(sizeof(*resp) + out.len);
	if (resp == NULL) {
		LOG(ERR, "cannot allocate %zu bytes for response payload", sizeof(*resp) + out.len);
		goto close;
	}
	resp->for_id = req.id;
	resp->status = out.status;
	resp->payload_len = out.len;
	if (resp_payload != NULL && out.len > 0) {
		memcpy(PAYLOAD(resp), resp_payload, out.len);
		free(resp_payload);
		resp_payload = NULL;
	}
	if (send_response(sock, resp) < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto retry_send;
		LOG(ERR, "send: %s", strerror(errno));
		goto close;
	}
	free(req_payload);
	free(resp);
	return;

retry_send:
	write_ev = event_new(ev_base, sock, EV_WRITE | EV_FINALIZE, api_write_cb, resp);
	if (write_ev == NULL || event_add(write_ev, NULL) < 0) {
		LOG(ERR, "failed to add event to loop");
		if (write_ev != NULL)
			event_free(write_ev);
		goto close;
	}
	free(req_payload);
	return;

close:
	free(req_payload);
	free(resp);
	if (ev != NULL)
		event_free_finalize(0, ev, finalize_close_fd);
}

static void listen_cb(evutil_socket_t sock, short what, void *ctx) {
	struct event *ev;
	int fd;

	(void)ctx;

	if (what & EV_CLOSED) {
		ev = event_base_get_running_event(ev_base);
		event_free_finalize(0, ev, finalize_close_fd);
		return;
	}

	if ((fd = accept4(sock, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			LOG(ERR, "accept: %s", strerror(errno));
		}
		return;
	}

	LOG(DEBUG, "new connection");

	ev = event_new(
		ev_base, fd, EV_READ | EV_CLOSED | EV_PERSIST | EV_FINALIZE, api_read_cb, NULL
	);
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
	struct event *ev_listen;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1) {
		LOG(ERR, "socket: %s", strerror(errno));
		return -1;
	}

	strncpy(addr.sun_path, br.api_sock_path, sizeof addr.sun_path - 1);

	if (bind(fd, (void *)&addr, sizeof addr) < 0) {
		LOG(ERR, "bind: %s: %s", br.api_sock_path, strerror(errno));
		close(fd);
		return -1;
	}

	if (listen(fd, BACKLOG) < 0) {
		LOG(ERR, "listen: %s: %s", br.api_sock_path, strerror(errno));
		close(fd);
		return -1;
	}

	ev_listen = event_new(
		ev_base,
		fd,
		EV_READ | EV_WRITE | EV_CLOSED | EV_PERSIST | EV_FINALIZE,
		listen_cb,
		NULL
	);
	if (ev_listen == NULL || event_add(ev_listen, NULL) < 0) {
		close(fd);
		LOG(ERR, "event_new: %s: %s", br.api_sock_path, strerror(errno));
		return -1;
	}

	LOG(INFO, "listening on API socket %s", br.api_sock_path);

	return 0;
}

int main(int argc, char **argv) {
	int ret = EXIT_FAILURE;

	if (parse_args(argc, argv) < 0)
		goto end;

	if (dpdk_init(&br) < 0)
		goto dpdk_stop;

	modules_init();

	if ((ev_base = event_base_new()) == NULL) {
		LOG(ERR, "event_base_new: %s", strerror(errno));
		goto shutdown;
	}

	if (listen_api_socket() < 0)
		goto shutdown;

	if (register_signals(ev_base) < 0)
		goto shutdown;

	// run until signal or fatal error
	if (event_base_dispatch(ev_base) == 0)
		ret = EXIT_SUCCESS;

shutdown:
	unregister_signals();
	if (ev_base)
		event_base_free(ev_base);
	unlink(br.api_sock_path);
	libevent_global_shutdown();
	modules_fini();
dpdk_stop:
	dpdk_fini();
end:
	return ret;
}
