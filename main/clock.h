// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 SmartShare Systems

#pragma once

#include <gr_clock.h>

#include <rte_branch_prediction.h>

#include <assert.h>
#include <stdatomic.h>

// (Internal) Per-thread snapshot of gr_clock_ns().
extern __thread gr_clock_ns_t clock_snapshot_ns;

// (Internal) Per-thread snapshot of gr_wallclock_ns().
extern __thread gr_wallclock_ns_t wallclock_snapshot_ns;

// (Internal) Offset from clock to wall clock.
// Automatically updated by clock tick event handler in the main event loop.
extern _Atomic gr_clock_ns_t clock_wallclock_offset;

// Update the clocks for the current thread.
static inline void clock_update(void) {
	clock_snapshot_ns = gr_clock_ns();
	wallclock_snapshot_ns = clock_snapshot_ns
		+ atomic_load_explicit(&clock_wallclock_offset, memory_order_relaxed);
}

// When true, assume that the clocks are updated for the current thread.
extern __thread bool clock_trusted;

// Update clock_trusted for the current thread.
static inline void clock_set_trusted(bool trusted) {
	clock_trusted = trusted;
}

// Get powered-on (non-suspended, non-hibernated) time since last boot [nanoseconds],
// using a common clock across all processes.
// Does not return negative values.
// Uses the low-overhead clock_snapshot_ns if clock_trusted is true.
// Otherwise, falls back to gr_clock_ns().
static inline gr_clock_ns_t clock_ns(void) {
	if (likely(clock_trusted)) {
		assert(clock_snapshot_ns > 0);
		return clock_snapshot_ns;
	}
	return gr_clock_ns();
}

// Get wall clock time [nanoseconds],
// relative to the UNIX epoch, a common clock across diverse systems.
// Returns incorrect values if the wall clock has not been set or is out of adjustment.
// May jump forwards or backwards, e.g. when the wall clock is set or adjusted by NTP.
// May jump slightly forwards or backwards, when the clock drifts from the wall clock.
// Does not return negative values.
// Uses the low-overhead clock_snapshot_ns and clock_wallclock_offset_snapshot
// if clock_trusted is true.
// Otherwise, falls back to gr_wallclock_ns().
static inline gr_wallclock_ns_t wallclock_ns(void) {
	if (likely(clock_trusted)) {
		assert(wallclock_snapshot_ns > 0);
		return wallclock_snapshot_ns;
	}
	return gr_wallclock_ns();
}
