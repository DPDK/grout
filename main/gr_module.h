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

struct api_ctx {
	struct gr_api_request header;
	bool header_complete;
	struct bufferevent *bev;
	pid_t pid;
	LIST_ENTRY(api_ctx) next;
};

void api_send(struct api_ctx *, uint32_t len, const void *payload);

typedef struct api_out (*gr_api_handler_func)(const void *request, struct api_ctx *);

void __gr_api_handler(uint32_t req_type, gr_api_handler_func callback, const char *name);

#define gr_api_handler(req_type, callback) __gr_api_handler(req_type, callback, #req_type)

struct gr_module {
	const char *name;
	const char *depends_on;
	void (*init)(struct event_base *);
	void (*fini)(struct event_base *);
	STAILQ_ENTRY(gr_module) next;
};

void gr_register_module(struct gr_module *);
