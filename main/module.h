// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_CONTROL_PRIV
#define _GR_CONTROL_PRIV

#include <gr_api.h>
#include <gr_module.h>

#include <event2/event.h>

const struct gr_api_handler *lookup_api_handler(const struct gr_api_request *);

void modules_init(struct event_base *);

void modules_fini(struct event_base *);

#endif
