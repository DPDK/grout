// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Maxime Leroy, Free Mobile

#pragma once

#include "config.h"

#include <rte_common.h>
#include <rte_config.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int rss_autoscale_port_state_get(
	uint16_t port_id,
	uint16_t *n_active,
	uint16_t *n_load_recommended,
	uint16_t *cap,
	uint16_t *floor,
	uint16_t *max_n,
	uint16_t *min_n
);

// True when the controller manages this port and its PMD exposes a
// scalable RETA. Queried at graph build time to gate datapath health
// tracking on ports that can actually be scaled.
bool rss_autoscale_port_enabled(uint16_t port_id);

// Number of RSS queues the controller currently feeds (0 if unmanaged).
// Queried at graph build time to mark RETA-deactivated rxqs inactive.
uint16_t rss_autoscale_port_n_active(uint16_t port_id);

#define RSS_AUTOSCALE_CONSEC_FULL 4
#define RSS_AUTOSCALE_CONSEC_EMPTY 10000

// Per-(port, queue) datapath health. Single-writer (rxq's worker),
// multi-reader (control). Cache-aligned to avoid false sharing
// between adjacent queues' workers.
struct __rte_cache_aligned rxq_health {
	uint16_t consec_full;
	uint16_t consec_empty;
	_Atomic(bool) saturated;
	_Atomic(bool) idle;
	_Atomic(bool) reset_pending; // control-set, worker clears consec_* on next poll
};

extern struct rxq_health rxq_health[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES_PER_PORT];

void rxq_health_notify_transition(void);

// Called from the rx datapath after rte_eth_rx_burst(). Atomics and
// notify are touched on edge transitions only (saturated/idle flips),
// so steady-state cost is one compare per burst. The counters are
// capped at their threshold so they never wrap. full_burst is the
// per-rxq saturation threshold computed at graph build time.
static inline void
rxq_health_update(uint16_t port_id, uint16_t queue_id, uint16_t n_pkts, uint16_t full_burst) {
	if (gr_config.rss_autoscale == 0)
		return;
	struct rxq_health *h = &rxq_health[port_id][queue_id];

	if (atomic_load_explicit(&h->reset_pending, memory_order_relaxed)) {
		atomic_store_explicit(&h->reset_pending, false, memory_order_relaxed);
		h->consec_full = 0;
		h->consec_empty = 0;
		atomic_store_explicit(&h->saturated, false, memory_order_relaxed);
		atomic_store_explicit(&h->idle, false, memory_order_relaxed);
	}

	if (n_pkts >= full_burst) {
		bool was_idle = (h->consec_empty >= RSS_AUTOSCALE_CONSEC_EMPTY);
		h->consec_empty = 0;
		if (was_idle) {
			atomic_store_explicit(&h->idle, false, memory_order_relaxed);
			rxq_health_notify_transition();
		}
		if (h->consec_full < RSS_AUTOSCALE_CONSEC_FULL) {
			h->consec_full++;
			if (h->consec_full == RSS_AUTOSCALE_CONSEC_FULL) {
				atomic_store_explicit(&h->saturated, true, memory_order_relaxed);
				rxq_health_notify_transition();
			}
		}
	} else if (n_pkts == 0) {
		bool was_saturated = (h->consec_full >= RSS_AUTOSCALE_CONSEC_FULL);
		h->consec_full = 0;
		if (was_saturated) {
			atomic_store_explicit(&h->saturated, false, memory_order_relaxed);
			rxq_health_notify_transition();
		}
		if (h->consec_empty < RSS_AUTOSCALE_CONSEC_EMPTY) {
			h->consec_empty++;
			if (h->consec_empty == RSS_AUTOSCALE_CONSEC_EMPTY) {
				atomic_store_explicit(&h->idle, true, memory_order_relaxed);
				rxq_health_notify_transition();
			}
		}
	} else {
		bool was_saturated = (h->consec_full >= RSS_AUTOSCALE_CONSEC_FULL);
		bool was_idle = (h->consec_empty >= RSS_AUTOSCALE_CONSEC_EMPTY);
		if (h->consec_full | h->consec_empty) {
			h->consec_full = 0;
			h->consec_empty = 0;
		}
		if (was_saturated) {
			atomic_store_explicit(&h->saturated, false, memory_order_relaxed);
			rxq_health_notify_transition();
		}
		if (was_idle) {
			atomic_store_explicit(&h->idle, false, memory_order_relaxed);
			rxq_health_notify_transition();
		}
	}
}
