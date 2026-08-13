// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Harrison Caldicott

#pragma once

#include <rte_mbuf.h>

#include <stdint.h>

typedef enum : uint8_t {
	GR_MBUF_FLOW_HASH_L2,
	GR_MBUF_FLOW_HASH_L3_L4,
	GR_MBUF_FLOW_HASH_RSS,
} gr_mbuf_flow_hash_mode_t;

// Calculate a software packet-flow hash, ignoring any hardware RSS value. The
// packet data must start with an Ethernet header. RSS mode hashes the same
// L3/L4 fields as L3_L4 mode.
uint32_t gr_mbuf_flow_hash_compute(const struct rte_mbuf *, gr_mbuf_flow_hash_mode_t);

// Return a stable packet-flow hash. The packet data must start with an
// Ethernet header. RSS mode uses a hardware hash when present and falls back
// to a software L3/L4 hash for virtual devices without RSS.
static inline uint32_t gr_mbuf_flow_hash(const struct rte_mbuf *m, gr_mbuf_flow_hash_mode_t mode) {
	if (likely(mode == GR_MBUF_FLOW_HASH_RSS && (m->ol_flags & RTE_MBUF_F_RX_RSS_HASH)))
		return m->hash.rss;
	return gr_mbuf_flow_hash_compute(m, mode);
}
