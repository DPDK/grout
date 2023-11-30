// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_SIGNALS
#define _BR_SIGNALS

#include <event2/event.h>

int register_signals(struct event_base *base);
void unregister_signals(void);

#endif
