// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 SmartShare Systems

#pragma once

#include <gr_clock.h>

#include <rte_branch_prediction.h>

#include <assert.h>

// Per-thread snapshot of gr_clock_ns().
extern __thread gr_clock_ns_t clock_snapshot_ns;

// Update the clock for the current thread.
static inline void clock_update(void) {
	clock_snapshot_ns = gr_clock_ns();
}

// When true, assume that the clock is updated for the current thread.
extern __thread bool clock_trusted;

// Update clock_trusted for the current thread.
static inline void clock_set_trusted(bool trusted) {
	clock_trusted = trusted;
}

// Get the current value of clock_snapshot_ns if clock_trusted is true.
// Otherwise, fallback to gr_clock_ns().
static inline gr_clock_ns_t clock_ns(void) {
	if (likely(clock_trusted)) {
		assert(clock_snapshot_ns > 0);
		return clock_snapshot_ns;
	}
	return gr_clock_ns();
}
