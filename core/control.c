// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "control.h"

#include <br_api.h>
#include <br_control.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

struct api_handler {
	uint32_t request_type;
	br_api_handler_t *callback;
};

#define MAX_API_HANDLERS 256
static struct api_handler handlers[MAX_API_HANDLERS];

void br_register_api_handler(uint32_t request_type, br_api_handler_t *callback) {
	int i;

	assert(request_type > 0);

	for (i = 0; i < MAX_API_HANDLERS && handlers[i].request_type != 0; i++)
		assert(handlers[i].request_type != request_type);

	assert(i < MAX_API_HANDLERS);

	handlers[i].request_type = request_type;
	handlers[i].callback = callback;
}

br_api_handler_t *br_lookup_api_handler(const struct br_api_request *req) {
	for (int i = 0; i < MAX_API_HANDLERS; i++) {
		struct api_handler *h = &handlers[i];
		if (h->request_type == req->type)
			return handlers[i].callback;
	}
	return NULL;
}
