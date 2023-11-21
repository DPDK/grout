// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "control-priv.h"

#include <br_api.h>
#include <br_control.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

struct service_handler {
	uint16_t service;
	br_service_handler_t *callback;
};

#define MAX_CONTROL_HANDLERS 256
static struct service_handler handlers[MAX_CONTROL_HANDLERS];

void br_register_service_handler(uint16_t service, br_service_handler_t *callback) {
	int i;

	assert(service > 0);

	for (i = 0; i < MAX_CONTROL_HANDLERS && handlers[i].service != 0; i++)
		assert(handlers[i].service != service);

	assert(i < MAX_CONTROL_HANDLERS);

	handlers[i].service = service;
	handlers[i].callback = callback;
}

br_service_handler_t *br_lookup_service_handler(uint32_t service) {
	for (int i = 0; i < MAX_CONTROL_HANDLERS && handlers[i].service != 0; i++) {
		if (handlers[i].service == service)
			return handlers[i].callback;
	}
	return NULL;
}
