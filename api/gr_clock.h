// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry
// Copyright (c) 2026 SmartShare Systems

#pragma once

#include <stdint.h>
#include <time.h>

// Clock source.
// Must be a high-resolution clock, i.e. not a _COARSE variant.
#define GR_CLOCK_SOURCE CLOCK_MONOTONIC_RAW

// High-resolution clock [nanoseconds].
// Used with GR_CLOCK_SOURCE, unless otherwise specified.
// Note: Does not have Y2038 problems. Not even with CLOCK_REALTIME.
// Note: Using signed, to avoid need for casting to signed
// in calculations where race conditions may cause negative differences.
typedef int64_t gr_clock_ns_t;

#define GR_NS_PER_S (gr_clock_ns_t)1000000000LL
#define GR_NS_PER_MS (gr_clock_ns_t)1000000LL
#define GR_NS_PER_US (gr_clock_ns_t)1000LL

// Get powered-on (non-suspended, non-hibernated) time since last boot [nanoseconds],
// using a common clock across all processes.
// Does not return negative values.
static inline gr_clock_ns_t gr_clock_ns(void) {
	struct timespec tp = {0};
	clock_gettime(GR_CLOCK_SOURCE, &tp);
	return tp.tv_sec * GR_NS_PER_S + tp.tv_nsec;
}
