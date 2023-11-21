// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_SIGNALS
#define _BR_SIGNALS

#include "br.h"

int register_signals(struct boring_router *);
void unregister_signals(struct boring_router *);

#endif
