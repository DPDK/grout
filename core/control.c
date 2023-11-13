// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "control.h"

#include <bro_api.h>
#include <bro_control.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

struct control_handler {
	uint32_t type;
	ctrl_handler_t *callback;
};

#define MAX_CONTROL_HANDLERS 256
static struct control_handler handlers[MAX_CONTROL_HANDLERS];

void bro_register_handler(uint32_t type, ctrl_handler_t *callback) {
	int i;

	assert(type > 0);

	for (i = 0; i < MAX_CONTROL_HANDLERS && handlers[i].type != 0; i++)
		assert(handlers[i].type != type);

	assert(i < MAX_CONTROL_HANDLERS);

	handlers[i].type = type;
	handlers[i].callback = callback;
}

ctrl_handler_t *lookup_control_handler(uint32_t type) {
	for (int i = 0; i < MAX_CONTROL_HANDLERS && handlers[i].type != 0; i++) {
		if (handlers[i].type == type)
			return handlers[i].callback;
	}
	return NULL;
}
