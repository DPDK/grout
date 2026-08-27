// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 SmartShare Systems

#include "clock.h"

__thread bool clock_trusted = false;

__thread gr_clock_ns_t clock_snapshot_ns = INT64_C(-1);
