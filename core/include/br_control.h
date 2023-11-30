// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CONTROL
#define _BR_CONTROL

#include <br_api.h>

#include <stdint.h>
#include <sys/queue.h>

typedef void(br_api_handler_cb_t)(void *req_payload, struct br_api_response *);

struct br_api_handler {
	const char *name;
	uint32_t request_type;
	br_api_handler_cb_t *callback;
	LIST_ENTRY(br_api_handler) entries;
};

void br_register_api_handler(struct br_api_handler *);

#endif
