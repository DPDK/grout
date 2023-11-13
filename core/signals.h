// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BROUTER_SIGNALS
#define _BROUTER_SIGNALS

#include "bro.h"

int register_signals(struct brouter *);
void unregister_signals(struct brouter *);

#endif
