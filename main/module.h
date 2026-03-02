// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_module.h>

#include <event2/event.h>

struct api_handler {
	gr_api_handler_func callback;
	const char *name;
};

const struct api_handler *lookup_api_handler(uint32_t request_type);

void modules_init(struct event_base *);

void modules_fini(struct event_base *);
