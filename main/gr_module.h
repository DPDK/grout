// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_api.h>

#include <event2/event.h>

#include <stdint.h>
#include <sys/queue.h>

struct api_out {
	uint32_t status;
	uint32_t len;
};

static inline struct api_out api_out(uint32_t status, uint32_t len) {
	struct api_out out = {status, len};
	return out;
}

struct api_ctx {
	struct gr_api_request header;
	bool header_complete;
	struct bufferevent *bev;
	LIST_ENTRY(api_ctx) next;
};

typedef struct api_out (*gr_api_handler_func)(const void *request, void **response);

struct gr_api_handler {
	const char *name;
	uint32_t request_type;
	gr_api_handler_func callback;
	STAILQ_ENTRY(gr_api_handler) entries;
};

void gr_register_api_handler(struct gr_api_handler *);

struct gr_module {
	const char *name;
	const char *depends_on;
	void (*init)(struct event_base *);
	void (*fini)(struct event_base *);
	STAILQ_ENTRY(gr_module) entries;
};

void gr_register_module(struct gr_module *);
