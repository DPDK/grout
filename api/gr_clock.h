// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry
// Copyright (c) 2026 SmartShare Systems

#pragma once

#include <stdint.h>
#include <time.h>

// High-resolution clock [nanoseconds].
// Used with CLOCK_MONOTONIC_RAW, unless otherwise specified.
// Note: Does not have Y2038 problems. Not even with CLOCK_REALTIME.
// Note: Using signed, to avoid need for casting to signed
// in calculations where race conditions may cause negative differences.
typedef int64_t gr_clock_ns_t;

// Get powered-on (non-suspended, non-hibernated) time since last boot,
// using a common clock across all processes.
static inline struct timespec gr_clock_raw(void) {
	struct timespec tp = {0};
	clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
	return tp;
}

#define GR_NS_PER_S (gr_clock_ns_t)1000000000LL

// Get powered-on (non-suspended, non-hibernated) time since last boot [nanoseconds],
// using a common clock across all processes.
// Does not return negative values.
static inline gr_clock_ns_t gr_clock_ns(void) {
	struct timespec tp = gr_clock_raw();
	return tp.tv_sec * GR_NS_PER_S + tp.tv_nsec;
}
