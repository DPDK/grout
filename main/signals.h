// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_SIGNALS
#define _GR_SIGNALS

#include <event2/event.h>

int register_signals(struct event_base *base);
void unregister_signals(void);

#endif
