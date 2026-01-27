// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "gr_metrics.h"
#include "unix.h"

#include <gr_config.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_vec.h>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

static STAILQ_HEAD(, gr_metrics_collector) collectors = STAILQ_HEAD_INITIALIZER(collectors);

void gr_metrics_register(struct gr_metrics_collector *c) {
	STAILQ_INSERT_TAIL(&collectors, c, next);
}

struct gr_metrics_writer {
	struct evbuffer *buf;
	// Pointers to static metrics that have had HELP/TYPE written.
	gr_vec const struct gr_metric **emitted;
};

static bool metric_emitted(const struct gr_metrics_writer *w, const struct gr_metric *m) {
	gr_vec_foreach (const struct gr_metric *e, w->emitted) {
		if (e == m)
			return true;
	}
	return false;
}

static void emit_help_type(struct gr_metrics_writer *w, const struct gr_metric *m) {
	const char *type_str;

	if (metric_emitted(w, m))
		return;

	switch (m->type) {
	case GR_METRIC_COUNTER:
		type_str = "counter";
		break;
	case GR_METRIC_GAUGE:
		type_str = "gauge";
		break;
	default:
		ABORT("unsupported metric type %u", m->type);
	}

	evbuffer_add_printf(w->buf, "# HELP grout_%s %s\n", m->name, m->help);
	evbuffer_add_printf(w->buf, "# TYPE grout_%s %s\n", m->name, type_str);
	gr_vec_add(w->emitted, m);
}

static void append_labels_va(struct gr_metrics_ctx *ctx, va_list ap) {
	const size_t len = sizeof(ctx->labels) - ctx->labels_len;
	char *buf = ctx->labels + ctx->labels_len;
	const char *key, *val;
	size_t n = 0;

	for (key = va_arg(ap, const char *); key != NULL; key = va_arg(ap, const char *)) {
		val = va_arg(ap, const char *);

		if (n > 0 || ctx->labels_len > 0)
			SAFE_BUF(snprintf, len, ",");

		SAFE_BUF(snprintf, len, "%s=\"%s\"", key, val ?: "");
	}

	ctx->labels_len += n;

	return;
err:
	LOG(ERR, "snprintf: %s", strerror(errno));
}

void gr_metrics_ctx_init(struct gr_metrics_ctx *ctx, struct gr_metrics_writer *w, ...) {
	va_list ap;

	ctx->w = w;
	ctx->labels_len = 0;
	ctx->labels[0] = '\0';

	va_start(ap, w);
	append_labels_va(ctx, ap);
	va_end(ap);
}

void gr_metrics_labels_add(struct gr_metrics_ctx *ctx, ...) {
	va_list ap;

	va_start(ap, ctx);
	append_labels_va(ctx, ap);
	va_end(ap);
}

void gr_metric_emit(struct gr_metrics_ctx *ctx, const struct gr_metric *m, uint64_t value) {
	emit_help_type(ctx->w, m);
	evbuffer_add_printf(ctx->w->buf, "grout_%s{%s} %lu\n", m->name, ctx->labels, value);
}

static void metrics_handler(struct evhttp_request *req, void *) {
	if (gr_config.log_level >= RTE_LOG_DEBUG) {
		struct evhttp_connection *conn = evhttp_request_get_connection(req);
		char *peer_addr = NULL;
		uint16_t peer_port = 0;
		if (conn != NULL)
			evhttp_connection_get_peer(conn, &peer_addr, &peer_port);
		LOG(DEBUG, "GET %s - %s:%u", evhttp_request_get_uri(req), peer_addr, peer_port);
	}

	struct gr_metrics_writer writer = {
		.buf = evbuffer_new(),
		.emitted = NULL,
	};
	if (writer.buf == NULL) {
		LOG(ERR, "evbuffer_new: %s", strerror(errno));
		evhttp_send_error(req, HTTP_INTERNAL, "Internal error");
		return;
	}

	struct gr_metrics_collector *col;
	STAILQ_FOREACH (col, &collectors, next)
		col->collect(&writer);

	evhttp_send_reply(req, HTTP_OK, NULL, writer.buf);

	gr_vec_free(writer.emitted);
	evbuffer_free(writer.buf);
}

static struct event_base *ev_base;
static pthread_t thread_id;

int gr_metrics_set_affinity(size_t set_size, const cpu_set_t *affinity) {
	if (thread_id == 0)
		return 0;
	return pthread_setaffinity_np(thread_id, set_size, affinity);
}

static int metrics_bind_http(struct evhttp *http) {
	errno = 0;
	if (evhttp_bind_socket(http, gr_config.metrics_addr, gr_config.metrics_port) < 0) {
		errno = errno ?: EADDRNOTAVAIL;
		LOG(ERR,
		    "bind %s:%u: %s",
		    gr_config.metrics_addr,
		    gr_config.metrics_port,
		    strerror(errno));
		return errno_set(errno);
	}

	return 0;
}

static int metrics_bind_unix(struct evhttp *http) {
	int fd;

	if ((fd = unix_listen(gr_config.metrics_addr)) < 0) {
		LOG(ERR, "Cannot bind metrics socket %s", gr_config.metrics_addr);
		return errno_set(errno);
	}

	if (evhttp_accept_socket(http, fd) < 0) {
		LOG(ERR, "accept: %s: %s", gr_config.metrics_addr, strerror(errno));
		close(fd);
		return errno_set(errno);
	}

	return 0;
}

static void *metrics_thread(void *) {
	struct evhttp *http = NULL;

	pthread_setname_np(pthread_self(), "grout:metrics");
	pthread_setaffinity_np(
		pthread_self(), sizeof(gr_config.control_cpus), &gr_config.control_cpus
	);

	ev_base = event_base_new();
	if (ev_base == NULL) {
		errno = errno ?: ENOMEM;
		LOG(ERR, "event_base_new: %s", strerror(errno));
		return NULL;
	}

	http = evhttp_new(ev_base);
	if (http == NULL) {
		errno = errno ?: ENOMEM;
		LOG(ERR, "evhttp_new: %s", strerror(errno));
		goto end;
	}

	evhttp_set_max_headers_size(http, 4096);
	evhttp_set_max_body_size(http, 0);
	evhttp_set_allowed_methods(http, EVHTTP_REQ_GET);
	evhttp_set_gencb(http, metrics_handler, NULL);
	evhttp_set_default_content_type(http, "text/plain; version=0.0.4; charset=utf-8");

	if (gr_config.metrics_port != 0) {
		if (metrics_bind_http(http))
			goto end;
		LOG(NOTICE,
		    "openmetrics exporter listening on tcp: %s:%d",
		    gr_config.metrics_addr,
		    gr_config.metrics_port);
	} else {
		if (metrics_bind_unix(http))
			goto end;
		LOG(NOTICE,
		    "openmetrics exporter listening on unix socket: %s",
		    gr_config.metrics_addr);
	}

	if (event_base_dispatch(ev_base) < 0) {
		errno = errno ?: EIO;
		LOG(ERR, "event_base_dispatch: %s", strerror(errno));
		goto end;
	}
	errno = 0;

end:
	if (http != NULL)
		evhttp_free(http);
	event_base_free(ev_base);
	ev_base = NULL;

	return NULL;
}

void gr_metrics_start(void) {
	if (gr_config.metrics_addr != NULL) {
		if (pthread_create(&thread_id, NULL, metrics_thread, NULL) != 0) {
			LOG(ERR, "pthread_create: %s", strerror(errno));
			thread_id = 0;
		}
	} else {
		LOG(INFO, "openmetrics exporter disabled");
	}
}

void gr_metrics_stop(void) {
	if (ev_base != NULL)
		event_base_loopbreak(ev_base);
	if (thread_id != 0) {
		pthread_join(thread_id, NULL);
		thread_id = 0;
	}
}
