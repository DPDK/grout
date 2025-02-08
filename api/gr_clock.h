// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#ifndef _GR_CLOCK
#define _GR_CLOCK

#include <stdint.h>
#include <time.h>

//! Get the elapsed time since last boot (using a common clock across all processes).
static inline struct timespec gr_clock_raw(void) {
	struct timespec tp = {0};
	clock_gettime(CLOCK_MONOTONIC_RAW, &tp);
	return tp;
}

//! Get elapsed time since last boot in microseconds.
static inline clock_t gr_clock_us(void) {
	struct timespec tp = gr_clock_raw();
	return (tp.tv_sec * CLOCKS_PER_SEC) + (tp.tv_nsec / 1000);
}

#endif
