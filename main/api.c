// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "api.h"
#include "module.h"

#include <gr_api.h>
#include <gr_config.h>
#include <gr_event.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_vec.h>
#include <gr_version.h>

#include <event2/event.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static pid_t socket_pid(int fd) {
	struct ucred cred;
	socklen_t len;

	len = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1)
		return errno_log(errno, "getsockopt(SO_PEERCRED)");

	return cred.pid;
}

struct subscription {
	bool suppress_self_events;
	evutil_socket_t sock;
	pid_t pid;
};

// List of subscribers to EVENT_TYPE_ALL
static struct subscription *all_events_subs;
// 2 dimensional array of subscribers to events.
//
// Example to get a list of sockets subscribed to ev_type = 0xacdc0102:
//
//                           GR_INFRA_MODULE
//                                  |
//                                  v
//           +-----------------------------------------------------+
//  mod_subs | 0 | 1 | 2 | ...  | 0xacdc |  ...  | 0xfffe | 0xffff |
//           +-----------------------------------------------------+
//             NULL    NULL         |              NULL     NULL
//                                  v
//                      struct module_subscribers
//                              sockets
//                             +--------+
//  GR_EVENT_IFACE_UNKNOWN     | 0x0000 |
//                             |--------|
//  GR_EVENT_IFACE_POST_ADD    | 0x0001 |
//                             |--------|
//                             | ...... |
//                             |--------|
//  GR_EVENT_NEXTHOP_UPDATE -> | 0x0102 | -> gr_vec of evutil_socket_t
//                             |--------|
//                             | ...... |
//                             |--------|
//                             | 0xfffe |
//                             |--------|
//                             | 0xffff |
//                             +--------+
//
struct module_subscribers {
	struct subscription *ev_subs[UINT16_MAX];
};
static struct module_subscribers *mod_subs[UINT16_MAX];
// PID of the current request while API handler is called.
static __thread pid_t cur_req_pid;

static void api_send_notifications(uint32_t ev_type, const void *obj) {
	struct subscription *ev_subs = NULL;
	struct module_subscribers *subs;
	struct subscription *s;
	struct gr_api_event e;
	void *data = NULL;
	uint16_t mod, ev;
	int len;

	mod = (ev_type >> 16) & 0xffff;
	ev = ev_type & 0xffff;
	subs = mod_subs[mod];
	if (subs != NULL)
		ev_subs = subs->ev_subs[ev];

	if (gr_vec_len(all_events_subs) == 0 && gr_vec_len(ev_subs) == 0) {
		// no subscribers
		return;
	}

	if ((len = gr_event_serialize(ev_type, obj, &data)) < 0) {
		LOG(ERR, "gr_event_serialize: %s", strerror(-len));
		return;
	}

	e.ev_type = ev_type;
	e.payload_len = len;

	gr_vec_foreach_ref (s, all_events_subs) {
		if (s->suppress_self_events && s->pid == cur_req_pid)
			continue;
		send(s->sock, &e, sizeof(e), MSG_DONTWAIT | MSG_NOSIGNAL);
		send(s->sock, data, len, MSG_DONTWAIT | MSG_NOSIGNAL);
	}
	gr_vec_foreach_ref (s, ev_subs) {
		if (s->suppress_self_events && s->pid == cur_req_pid)
			continue;
		send(s->sock, &e, sizeof(e), MSG_DONTWAIT | MSG_NOSIGNAL);
		send(s->sock, data, len, MSG_DONTWAIT | MSG_NOSIGNAL);
	}

	free(data);
}

static struct api_out subscribe(evutil_socket_t sock, const void *request) {
	const struct gr_event_subscribe_req *req = request;
	struct module_subscribers *subs;
	struct subscription sub = {
		.sock = sock,
		.pid = socket_pid(sock),
		.suppress_self_events = req->suppress_self_events,
	};
	struct subscription *s;
	uint16_t mod, ev;

	if (req->ev_type == EVENT_TYPE_ALL) {
		gr_vec_foreach_ref (s, all_events_subs) {
			if (s->sock == sock) {
				s->suppress_self_events = req->suppress_self_events;
				return api_out(0, 0); // already subscribed
			}
		}
		gr_vec_add(all_events_subs, sub);
		return api_out(0, 0);
	}

	mod = (req->ev_type >> 16) & 0xffff;
	ev = req->ev_type & 0xffff;
	subs = mod_subs[mod];

	if (subs == NULL) {
		mod_subs[mod] = subs = calloc(1, sizeof(*subs));
		if (subs == NULL)
			return api_out(ENOMEM, 0);
	}
	gr_vec_foreach_ref (s, subs->ev_subs[ev]) {
		if (s->sock == sock) {
			s->suppress_self_events = req->suppress_self_events;
			return api_out(0, 0); // already subscribed
		}
	}
	gr_vec_add(subs->ev_subs[ev], sub);

	return api_out(0, 0);
}

static struct api_out unsubscribe(evutil_socket_t sock) {
	unsigned i;

	i = 0;
	while (i < gr_vec_len(all_events_subs)) {
		if (all_events_subs[i].sock == sock)
			gr_vec_del_swap(all_events_subs, i);
		else
			i++;
	}

	for (uint16_t mod = 0; mod < ARRAY_DIM(mod_subs); mod++) {
		struct module_subscribers *subs = mod_subs[mod];
		if (subs == NULL)
			continue;
		for (uint16_t ev = 0; ev < ARRAY_DIM(subs->ev_subs); ev++) {
			struct subscription *ev_subs = subs->ev_subs[ev];
			i = 0;
			while (i < gr_vec_len(ev_subs)) {
				if (ev_subs[i].sock == sock)
					gr_vec_del_swap(ev_subs, i);
				else
					i++;
			}
		}
	}

	return api_out(0, 0);
}

static struct api_out hello(const void *request) {
	const struct gr_hello_req *req = request;

	if (strncmp(req->version, GROUT_VERSION, sizeof(req->version)) != 0)
		return api_out(EPROTO, 0);

	return api_out(0, 0);
}

static void finalize_fd(struct event *ev, void * /*priv*/) {
	int fd = event_get_fd(ev);
	if (fd >= 0)
		close(fd);
}

static ssize_t send_response(evutil_socket_t sock, struct gr_api_response *resp) {
	if (resp == NULL)
		return errno_set(ENOMEM);

	LOG(DEBUG,
	    "fd=%d for_id=%u len=%u status=%u %s",
	    sock,
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

	LOG(DEBUG, "fd=%d id=%u req_type=0x%08x len=%u", sock, req.id, req.type, req.payload_len);

	switch (req.type) {
	case GR_MAIN_HELLO:
		out = hello(req_payload);
		goto send;
	case GR_MAIN_EVENT_SUBSCRIBE:
		out = subscribe(sock, req_payload);
		goto send;
	case GR_MAIN_EVENT_UNSUBSCRIBE:
		out = unsubscribe(sock);
		goto send;
	}

	const struct gr_api_handler *handler = lookup_api_handler(&req);
	if (handler == NULL) {
		out.status = ENOTSUP;
		out.len = 0;
		goto send;
	}

	cur_req_pid = socket_pid(sock);
	out = handler->callback(req_payload, &resp_payload);
	cur_req_pid = 0;

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
	unsubscribe(sock);
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

	LOG(DEBUG, "new connection fd=%d", fd);

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
	const char *path = gr_config.api_sock_path;
	union {
		struct sockaddr_un un;
		struct sockaddr a;
	} addr;
	int ret;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1)
		return errno_log(errno, "socket");

	addr.un.sun_family = AF_UNIX;
	memccpy(addr.un.sun_path, path, 0, sizeof(addr.un.sun_path) - 1);

	ret = bind(fd, &addr.a, sizeof(addr.un));
	if (ret < 0 && errno == EADDRINUSE) {
		// unix socket file exists, check if there is a process
		// listening on the other side.
		ret = connect(fd, &addr.a, sizeof(addr.un));
		if (ret == 0) {
			LOG(ERR, "grout already running on API socket %s, exiting", path);
			close(fd);
			return errno_set(EADDRINUSE);
		}
		if (ret < 0 && errno != ECONNREFUSED)
			return errno_log(errno, "connect");
		// remove socket file, and try to bind again
		if (unlink(addr.un.sun_path) < 0)
			return errno_log(errno, "unlink");
		ret = bind(fd, &addr.a, sizeof(addr.un));
	}
	if (ret < 0) {
		close(fd);
		return errno_log(errno, "bind");
	}

	if (chown(path, gr_config.api_sock_uid, gr_config.api_sock_gid) < 0) {
		close(fd);
		return errno_log(errno, "API socket ownership can not be set");
	}

	if (chmod(path, gr_config.api_sock_mode) < 0) {
		close(fd);
		return errno_log(errno, "API socket permission can not be set");
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

static struct gr_event_subscription ev_subscribtion = {
	.callback = api_send_notifications,
	.ev_count = 1,
	.ev_types = {EVENT_TYPE_ALL},
};

RTE_INIT(init) {
	gr_event_subscribe(&ev_subscribtion);
}
