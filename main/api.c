// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "api.h"
#include "gr.h"
#include "module.h"

#include <gr_api.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_vec.h>

#include <event2/event.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void finalize_fd(struct event *ev, void * /*priv*/) {
	int fd = event_get_fd(ev);
	if (fd >= 0)
		close(fd);
}

static ssize_t send_response(evutil_socket_t sock, struct gr_api_response *resp) {
	if (resp == NULL)
		return errno_set(ENOMEM);

	LOG(DEBUG,
	    "for_id=%u len=%u status=%u %s",
	    resp->for_id,
	    resp->payload_len,
	    resp->status,
	    strerror(resp->status));

	size_t len = sizeof(*resp) + resp->payload_len;
	return send(sock, resp, len, MSG_DONTWAIT | MSG_NOSIGNAL);
}

// This is allocated in main() but we need a reference here.
// write_cb() needs both struct event_base AND struct gr_api_response and we
// cannot pass two private pointers.
static struct event_base *ev_base;

static void write_cb(evutil_socket_t sock, short /*what*/, void *priv) {
	struct event *ev = event_base_get_running_event(ev_base);
	struct gr_api_response *resp = priv;

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

static void read_cb(evutil_socket_t sock, short what, void * /*priv*/) {
	struct event *ev = event_base_get_running_event(ev_base);
	void *req_payload = NULL, *resp_payload = NULL;
	struct gr_api_response *resp = NULL;
	struct gr_api_request req;
	struct event *write_ev;
	struct api_out out;
	ssize_t len;

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
	if (req.payload_len > GR_API_MAX_MSG_LEN) {
		LOG(ERR, "recv: %s", strerror(EMSGSIZE));
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

	const struct gr_api_handler *handler = lookup_api_handler(&req);
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
	write_ev = event_new(ev_base, sock, EV_WRITE | EV_FINALIZE, write_cb, resp);
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
		event_free_finalize(0, ev, finalize_fd);
}

static void listen_cb(evutil_socket_t sock, short what, void * /*priv*/) {
	struct event *ev;
	int fd;

	if (what & EV_CLOSED) {
		ev = event_base_get_running_event(ev_base);
		event_free_finalize(0, ev, finalize_fd);
		return;
	}

	if ((fd = accept4(sock, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			LOG(ERR, "accept: %s", strerror(errno));
		}
		return;
	}

	LOG(DEBUG, "new connection");

	ev = event_new(ev_base, fd, EV_READ | EV_CLOSED | EV_PERSIST | EV_FINALIZE, read_cb, NULL);
	if (ev == NULL || event_add(ev, NULL) < 0) {
		LOG(ERR, "failed to add event to loop");
		if (ev != NULL)
			event_free(ev);
		close(fd);
	}
}

#define SOCKET_LISTEN_BACKLOG 16
static struct event *ev_listen;

int api_socket_start(struct event_base *base) {
	const char *path = gr_args()->api_sock_path;
	union {
		struct sockaddr_un un;
		struct sockaddr a;
	} addr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1)
		return errno_log(errno, "socket");

	addr.un.sun_family = AF_UNIX;
	memccpy(addr.un.sun_path, path, 0, sizeof(addr.un.sun_path) - 1);

	if (bind(fd, &addr.a, sizeof(addr.un)) < 0) {
		close(fd);
		return errno_log(errno, "bind");
	}

	if (listen(fd, SOCKET_LISTEN_BACKLOG) < 0) {
		close(fd);
		return errno_log(errno, "listen");
	}

	ev_listen = event_new(
		base, fd, EV_READ | EV_WRITE | EV_CLOSED | EV_PERSIST | EV_FINALIZE, listen_cb, NULL
	);
	if (ev_listen == NULL || event_add(ev_listen, NULL) < 0) {
		close(fd);
		return errno_log(errno, "event_new");
	}
	// keep a reference for callbacks
	ev_base = base;

	LOG(INFO, "listening on API socket %s", path);

	return 0;
}

static int collect_clients(const struct event_base *, const struct event *ev, void *priv) {
	struct event ***events = priv;
	event_callback_fn cb = event_get_callback(ev);
	if (cb == read_cb || cb == write_cb)
		gr_vec_add(*events, (struct event *)ev);
	return 0;
}

void api_socket_stop(struct event_base *) {
	struct event **events = NULL;
	struct event *ev;

	if (ev_listen != NULL)
		event_free_finalize(0, ev_listen, finalize_fd);

	event_base_foreach_event(ev_base, collect_clients, &events);
	gr_vec_foreach (ev, events)
		event_free_finalize(0, ev, finalize_fd);
	gr_vec_free(events);
}
