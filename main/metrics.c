// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "config.h"
#include "log.h"
#include "metrics.h"
#include "unix.h"
#include "vec.h"

#include <gr_macro.h>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>

#include <pthread.h>
#include <stdarg.h>
#include <string.h>

LOG_TYPE("main");

static STAILQ_HEAD(, metrics_collector) collectors = STAILQ_HEAD_INITIALIZER(collectors);

void metrics_register(struct metrics_collector *c) {
	STAILQ_INSERT_TAIL(&collectors, c, next);
}

struct metrics_writer {
	struct evbuffer *buf;
	// Pointers to static metrics that have had HELP/TYPE written.
	vec const struct metric **emitted;
};

static bool metric_emitted(const struct metrics_writer *w, const struct metric *m) {
	vec_foreach (const struct metric *e, w->emitted) {
		if (e == m)
			return true;
	}
	return false;
}

static void emit_help_type(struct metrics_writer *w, const struct metric *m) {
	const char *type_str;

	if (metric_emitted(w, m))
		return;

	switch (m->type) {
	case METRIC_COUNTER:
		type_str = "counter";
		break;
	case METRIC_GAUGE:
		type_str = "gauge";
		break;
	case METRIC_HISTOGRAM:
		type_str = "histogram";
		break;
	default:
		ABORT("unsupported metric type %u", m->type);
	}

	evbuffer_add_printf(w->buf, "# HELP grout_%s %s\n", m->name, m->help);
	evbuffer_add_printf(w->buf, "# TYPE grout_%s %s\n", m->name, type_str);
	vec_add(w->emitted, m);
}

static void append_labels_va(struct metrics_ctx *ctx, va_list ap) {
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

void metrics_ctx_init(struct metrics_ctx *ctx, struct metrics_writer *w, ...) {
	va_list ap;

	ctx->w = w;
	ctx->labels_len = 0;
	ctx->labels[0] = '\0';

	va_start(ap, w);
	append_labels_va(ctx, ap);
	va_end(ap);
}

void metrics_labels_add(struct metrics_ctx *ctx, ...) {
	va_list ap;

	va_start(ap, ctx);
	append_labels_va(ctx, ap);
	va_end(ap);
}

void metric_emit(struct metrics_ctx *ctx, const struct metric *m, uint64_t value) {
	emit_help_type(ctx->w, m);
	evbuffer_add_printf(ctx->w->buf, "grout_%s{%s} %lu\n", m->name, ctx->labels, value);
}

void metric_emit_histogram(
	struct metrics_ctx *ctx,
	const struct metric *m,
	const uint64_t *slot_counts,
	unsigned n_slots,
	const unsigned *bucket_bounds,
	unsigned n_buckets
) {
	emit_help_type(ctx->w, m);

	uint64_t cumulative = 0;
	uint64_t sum = 0;
	unsigned slot = 0;

	for (unsigned b = 0; b < n_buckets; b++) {
		unsigned le = bucket_bounds[b];
		while (slot < n_slots && slot <= le) {
			cumulative += slot_counts[slot];
			sum += slot_counts[slot] * slot;
			slot++;
		}
		evbuffer_add_printf(
			ctx->w->buf,
			"grout_%s_bucket{%s,le=\"%u\"} %lu\n",
			m->name,
			ctx->labels,
			le,
			cumulative
		);
	}

	// accumulate remaining slots beyond the last bucket bound
	while (slot < n_slots) {
		cumulative += slot_counts[slot];
		sum += slot_counts[slot] * slot;
		slot++;
	}

	evbuffer_add_printf(
		ctx->w->buf,
		"grout_%s_bucket{%s,le=\"+Inf\"} %lu\n",
		m->name,
		ctx->labels,
		cumulative
	);
	evbuffer_add_printf(ctx->w->buf, "grout_%s_sum{%s} %lu\n", m->name, ctx->labels, sum);
	evbuffer_add_printf(
		ctx->w->buf, "grout_%s_count{%s} %lu\n", m->name, ctx->labels, cumulative
	);
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

	struct metrics_writer writer = {
		.buf = evbuffer_new(),
		.emitted = NULL,
	};
	if (writer.buf == NULL) {
		LOG(ERR, "evbuffer_new: %s", strerror(errno));
		evhttp_send_error(req, HTTP_INTERNAL, "Internal error");
		return;
	}

	struct metrics_collector *col;
	STAILQ_FOREACH (col, &collectors, next)
		col->collect(&writer);

	evhttp_send_reply(req, HTTP_OK, NULL, writer.buf);

	vec_free(writer.emitted);
	evbuffer_free(writer.buf);
}

static struct event_base *ev_base;
static pthread_t thread_id;

int metrics_set_affinity(size_t set_size, const cpu_set_t *affinity) {
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

void metrics_start(void) {
	if (gr_config.metrics_addr != NULL) {
		if (pthread_create(&thread_id, NULL, metrics_thread, NULL) != 0) {
			LOG(ERR, "pthread_create: %s", strerror(errno));
			thread_id = 0;
		}
	} else {
		LOG(INFO, "openmetrics exporter disabled");
	}
}

void metrics_stop(void) {
	if (ev_base != NULL)
		event_base_loopbreak(ev_base);
	if (thread_id != 0) {
		pthread_join(thread_id, NULL);
		thread_id = 0;
	}
}
