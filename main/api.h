// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_MAIN_API
#define _GR_MAIN_API

#include <event2/event.h>

int api_socket_start(struct event_base *);
void api_socket_stop(struct event_base *);

#endif
