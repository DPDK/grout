// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "api.h"
#include "module.h"

#include <gr_api.h>
#include <gr_config.h>
#include <gr_event.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_queue.h>
#include <gr_vec.h>
#include <gr_version.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

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
	struct bufferevent *bev;
	pid_t pid;
};

// List of subscribers to EVENT_TYPE_ALL
static gr_vec struct subscription *all_events_subs;
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
	gr_vec struct subscription *ev_subs[UINT16_MAX];
};
static struct module_subscribers *mod_subs[UINT16_MAX];
static LIST_HEAD(, api_ctx) clients = LIST_HEAD_INITIALIZER(clients);
// PID of the current request while API handler is called.
static __thread pid_t cur_req_pid;
static __thread struct bufferevent *cur_req_bev;

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
		bufferevent_write(s->bev, &e, sizeof(e));
		bufferevent_write(s->bev, data, len);
	}
	gr_vec_foreach_ref (s, ev_subs) {
		if (s->suppress_self_events && s->pid == cur_req_pid)
			continue;
		bufferevent_write(s->bev, &e, sizeof(e));
		bufferevent_write(s->bev, data, len);
	}

	free(data);
}

static struct api_out subscribe(const void *request, void ** /*response*/) {
	const struct gr_event_subscribe_req *req = request;
	struct module_subscribers *subs;
	struct subscription sub = {
		.bev = cur_req_bev,
		.pid = cur_req_pid,
		.suppress_self_events = req->suppress_self_events,
	};
	struct subscription *s;
	uint16_t mod, ev;

	if (req->ev_type == EVENT_TYPE_ALL) {
		gr_vec_foreach_ref (s, all_events_subs) {
			if (s->bev == cur_req_bev) {
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
		if (s->bev == cur_req_bev) {
			s->suppress_self_events = req->suppress_self_events;
			return api_out(0, 0); // already subscribed
		}
	}
	gr_vec_add(subs->ev_subs[ev], sub);

	return api_out(0, 0);
}

static struct gr_api_handler subscribe_handler = {
	.request_type = GR_MAIN_EVENT_SUBSCRIBE,
	.callback = subscribe,
	.name = "event subscribe"
};

static struct api_out unsubscribe(const void * /*request*/, void ** /*response*/) {
	unsigned i;

	i = 0;
	while (i < gr_vec_len(all_events_subs)) {
		if (all_events_subs[i].bev == cur_req_bev)
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
				if (ev_subs[i].bev == cur_req_bev)
					gr_vec_del_swap(ev_subs, i);
				else
					i++;
			}
		}
	}

	return api_out(0, 0);
}

static struct gr_api_handler unsubscribe_handler = {
	.request_type = GR_MAIN_EVENT_UNSUBSCRIBE,
	.callback = unsubscribe,
	.name = "event unsubscribe"
};

static struct api_out hello(const void *request, void ** /*response*/) {
	const struct gr_hello_req *req = request;

	if (strncmp(req->version, GROUT_VERSION, sizeof(req->version)) != 0)
		return api_out(EPROTO, 0);

	return api_out(0, 0);
}

static struct gr_api_handler hello_handler = {
	.request_type = GR_MAIN_HELLO,
	.callback = hello,
	.name = "hello"
};

static void disconnect_client(struct api_ctx *ctx) {
	assert(ctx != NULL);
	assert(ctx->bev != NULL);

	LIST_REMOVE(ctx, next);

	LOG(DEBUG, "client fd=%d disconnected", bufferevent_getfd(ctx->bev));

	// Clean up subscriptions for this client
	cur_req_bev = ctx->bev;
	unsubscribe(NULL, NULL);
	cur_req_bev = NULL;

	bufferevent_free(ctx->bev);
	free(ctx);
}

static void read_cb(struct bufferevent *bev, void *priv) {
	struct evbuffer *input = bufferevent_get_input(bev);
	void *req_payload = NULL, *resp_payload = NULL;
	struct api_ctx *ctx = priv;
	struct api_out out;
	int sock;

	assert(ctx != NULL);

	// Read header if we haven't already
	if (!ctx->header_complete) {
		if (evbuffer_get_length(input) < sizeof(ctx->header))
			return; // Wait for more data

		// Read the request header
		if (evbuffer_remove(input, &ctx->header, sizeof(ctx->header)) < 0) {
			LOG(ERR, "failed to read request header");
			goto close;
		}

		if (ctx->header.payload_len > GR_API_MAX_MSG_LEN) {
			LOG(ERR, "request payload too large: %u", ctx->header.payload_len);
			goto close;
		}

		ctx->header_complete = true;
	}

	if (evbuffer_get_length(input) < ctx->header.payload_len) {
		return; // Wait for more data
	} else if (ctx->header.payload_len > 0) {
		req_payload = malloc(ctx->header.payload_len);
		if (req_payload == NULL) {
			LOG(ERR,
			    "cannot allocate %u bytes for request payload",
			    ctx->header.payload_len);
			goto close;
		}
		if (evbuffer_remove(input, req_payload, ctx->header.payload_len) < 0) {
			LOG(ERR, "failed to read request payload");
			goto close;
		}
	}

	// Reset state for next request
	ctx->header_complete = false;

	// We have a complete request, process it
	sock = bufferevent_getfd(bev);
	const struct gr_api_handler *handler = lookup_api_handler(&ctx->header);
	if (handler == NULL) {
		out.status = ENOTSUP;
		out.len = 0;
		goto send;
	}

	cur_req_pid = socket_pid(sock);
	cur_req_bev = bev;
	out = handler->callback(req_payload, &resp_payload);
	cur_req_pid = 0;
	cur_req_bev = NULL;

send:
	LOG(DEBUG,
	    "fd=%d id=%u req_type=0x%08x (%s) req_len=%u status=%d (%s) resp_len=%u",
	    sock,
	    ctx->header.id,
	    ctx->header.type,
	    handler ? handler->name : "?",
	    ctx->header.payload_len,
	    out.status,
	    strerror(out.status),
	    out.len);

	struct gr_api_response resp = {
		.for_id = ctx->header.id,
		.status = out.status,
		.payload_len = out.len,
	};

	if (bufferevent_write(bev, &resp, sizeof(resp)) < 0)
		LOG(ERR, "failed to write header");
	if (out.len > 0) {
		assert(resp_payload != NULL);
		if (bufferevent_write(bev, resp_payload, out.len) < 0)
			LOG(ERR, "failed to write payload");
	}

	bufferevent_flush(bev, EV_WRITE, BEV_FLUSH);

	free(req_payload);
	free(resp_payload);

	if (evbuffer_get_length(input) >= sizeof(ctx->header)) {
		// More data is available in the input buffer.
		// Force read_cb to be invoked again when possible.
		bufferevent_flush(bev, EV_READ, BEV_NORMAL);
	}
	return;

close:
	free(req_payload);
	free(resp_payload);
	disconnect_client(ctx);
}

static void event_cb(struct bufferevent *bev, short events, void *priv) {
	assert(priv != NULL);

	if (events & BEV_EVENT_ERROR)
		LOG(ERR, "bufferevent error on fd=%d: %s", bufferevent_getfd(bev), strerror(errno));

	if (events & BEV_EVENT_EOF)
		disconnect_client(priv);
}

static void accept_conn_cb(
	struct evconnlistener *,
	evutil_socket_t fd,
	struct sockaddr *,
	int /*socklen*/,
	void *priv
) {
	struct event_base *base = priv;
	struct bufferevent *bev;
	struct api_ctx *ctx;

	bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (bev == NULL) {
		LOG(ERR, "failed to create bufferevent for fd=%d", fd);
		close(fd);
		return;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		LOG(ERR, "failed to allocate client context for fd=%d", fd);
		bufferevent_free(bev);
		return;
	}

	ctx->bev = bev;

	LOG(DEBUG, "new connection fd=%d", fd);

	bufferevent_setwatermark(
		bev, EV_READ, 0, sizeof(struct gr_api_request) + GR_API_MAX_MSG_LEN
	);
	bufferevent_setwatermark(
		bev, EV_WRITE, 0, sizeof(struct gr_api_response) + GR_API_MAX_MSG_LEN
	);
	bufferevent_setcb(bev, read_cb, NULL, event_cb, ctx);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	LIST_INSERT_HEAD(&clients, ctx, next);
}

#define SOCKET_LISTEN_BACKLOG 16
static struct evconnlistener *listener;

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

	listener = evconnlistener_new(
		base, accept_conn_cb, base, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 0, fd
	);
	if (listener == NULL) {
		close(fd);
		return errno_log(errno, "evconnlistener_new");
	}

	LOG(INFO, "listening on API socket %s", path);

	return 0;
}

void api_socket_stop(struct event_base *) {
	if (listener != NULL) {
		// Stop listening for new connections.
		evconnlistener_free(listener);
		listener = NULL;
	}

	// Gracefully disconnect all clients.
	struct api_ctx *ctx, *tmp;
	LIST_FOREACH_SAFE (ctx, &clients, next, tmp)
		disconnect_client(ctx);
}

static struct gr_event_subscription ev_subscribtion = {
	.callback = api_send_notifications,
	.ev_count = 1,
	.ev_types = {EVENT_TYPE_ALL},
};

RTE_INIT(init) {
	gr_event_subscribe(&ev_subscribtion);
	gr_register_api_handler(&subscribe_handler);
	gr_register_api_handler(&unsubscribe_handler);
	gr_register_api_handler(&hello_handler);
}
