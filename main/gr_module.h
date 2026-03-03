// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_api.h>

#include <event2/bufferevent.h>
#include <event2/event.h>

#include <stdint.h>
#include <sys/queue.h>

struct api_out {
	uint32_t status;
	uint32_t len;
	void *payload;
};

static inline struct api_out api_out(uint32_t status, uint32_t len, void *payload) {
	struct api_out out = {status, len, payload};
	return out;
}

struct api_ctx;

// Streaming handler callbacks. init() allocates cursor state from
// the request. next() advances the cursor and sends one item via
// api_send() which returns STREAM_MORE on success. The
// framework always calls free() to free cursor state when the
// stream ends. Typical next() pattern:
//
//   if (no_more_items)
//       return STREAM_END;
//   return api_send(ctx, len, payload);
typedef void *(*stream_init_func)(const void *request, struct api_ctx *);
typedef int (*stream_next_func)(void *state, struct api_ctx *);

typedef struct api_out (*gr_api_handler_func)(const void *request, struct api_ctx *);

struct api_ctx {
	struct gr_api_request header;
	bool header_complete;
	struct bufferevent *bev;
	pid_t pid;
	LIST_ENTRY(api_ctx) next;
	// active stream state (NULL if no stream)
	void *stream_state;
	uint32_t stream_req_id;
	stream_next_func stream_next;
};

void api_send(struct api_ctx *, uint32_t len, const void *payload);

void __gr_api_handler(uint32_t req_type, gr_api_handler_func callback, const char *name);

#define gr_api_handler(req_type, callback) __gr_api_handler(req_type, callback, #req_type)

enum {
	// negative values = errno, stream done with error
	STREAM_END = 0, // no more items, stream done (success)
	STREAM_MORE = 1, // item sent, buffer has room
	STREAM_PAUSE = 2, // item sent, buffer full (pause production)
};

int api_stream_next(struct api_ctx *, uint32_t len, const void *payload);

void __gr_api_handler_stream(
	uint32_t req_type,
	stream_init_func init,
	stream_next_func next,
	const char *name
);

#define gr_api_handler_stream(req_type, init, next)                                                \
	__gr_api_handler_stream(req_type, init, next, #req_type)

struct gr_module {
	const char *name;
	const char *depends_on;
	void (*init)(struct event_base *);
	void (*fini)(struct event_base *);
	STAILQ_ENTRY(gr_module) next;
};

void gr_register_module(struct gr_module *);
