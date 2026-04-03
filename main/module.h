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

typedef struct api_out (*api_handler_func)(const void *request, struct api_ctx *);

void __api_handler(uint32_t req_type, api_handler_func callback, const char *name, size_t req_size);

// Register an API handler with expected minimum request payload size.
#define api_handler(req_type, callback)                                                            \
	__api_handler(req_type, callback, #req_type, req_type##_REQ_SIZE)

struct module {
	const char *name;
	const char *depends_on;
	void (*init)(struct event_base *);
	void (*fini)(struct event_base *);
	STAILQ_ENTRY(module) next;
};

void module_register(struct module *);

struct api_handler {
	api_handler_func callback;
	const char *name;
	size_t req_size; // minimum expected payload size, 0 if no payload
};

const struct api_handler *lookup_api_handler(uint32_t request_type);

void modules_init(struct event_base *);

void modules_fini(struct event_base *);
