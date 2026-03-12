// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_module.h>

#include <event2/event.h>

struct api_handler {
	gr_api_handler_func callback;
	const char *name;
	// stream handler callbacks (mutually exclusive with callback)
	stream_init_func stream_init;
	stream_next_func stream_next; // returns STREAM_NEXT, STREAM_END, or -errno
};

const struct api_handler *lookup_api_handler(uint32_t request_type);

void modules_init(struct event_base *);

void modules_fini(struct event_base *);
