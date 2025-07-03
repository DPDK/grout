// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <event2/event.h>

int register_signals(struct event_base *base);
void unregister_signals(void);
