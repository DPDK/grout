// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CONTROL
#define _BR_CONTROL

#include <stdint.h>
#include <sys/queue.h>

struct api_out {
	uint32_t code;
	uint32_t len;
};

static inline struct api_out api_out(uint32_t code, uint32_t len) {
	struct api_out out = {code, len};
	return out;
}

typedef struct api_out(br_api_handler_cb_t)(const void *request, void *response);

struct br_api_handler {
	const char *name;
	uint32_t request_type;
	br_api_handler_cb_t *callback;
	LIST_ENTRY(br_api_handler) entries;
};

void br_register_api_handler(struct br_api_handler *);

#endif
