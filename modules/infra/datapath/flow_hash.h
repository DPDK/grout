// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Harrison Caldicott

#pragma once

#include <rte_mbuf.h>

#include <stdbool.h>
#include <stdint.h>

typedef enum : uint8_t {
	GR_MBUF_FLOW_HASH_L2,
	GR_MBUF_FLOW_HASH_L3_L4,
	GR_MBUF_FLOW_HASH_RSS,
} gr_mbuf_flow_hash_mode_t;

// Calculate a packet-flow hash without caching it. The packet data must start
// with an Ethernet header. RSS mode uses a hardware hash when present and falls
// back to a software L3/L4 hash for virtual devices without RSS.
uint32_t gr_mbuf_flow_hash(const struct rte_mbuf *, gr_mbuf_flow_hash_mode_t);

static inline bool gr_mbuf_flow_hash_is_valid(const struct rte_mbuf *m) {
	return m->ol_flags & RTE_MBUF_F_RX_RSS_HASH;
}

// Store a software flow hash where a hardware driver would have put its RSS
// value, so every consumer reads m->hash.rss the same way.
static inline void gr_mbuf_flow_hash_set(struct rte_mbuf *m, uint32_t hash) {
	m->hash.rss = hash;
	m->ol_flags |= RTE_MBUF_F_RX_RSS_HASH;
}

// Drop a hash that no longer describes the packet, typically after tunnel
// decapsulation exposed an inner frame. The next consumer recomputes a
// software hash on demand.
static inline void gr_mbuf_flow_hash_invalidate(struct rte_mbuf *m) {
	m->ol_flags &= ~RTE_MBUF_F_RX_RSS_HASH;
}

// Same as gr_mbuf_flow_hash() in L3/L4 mode for packets whose data starts
// with an IPv4 or IPv6 header. eth_type must match that header.
uint32_t gr_mbuf_flow_hash_l3(const struct rte_mbuf *, rte_be16_t eth_type);

// Return the flow hash of an Ethernet-framed packet. A hash already present
// in m->hash.rss is returned as is; otherwise a software L3/L4 hash is
// calculated once and cached there.
static inline uint32_t gr_mbuf_flow_hash_get(struct rte_mbuf *m) {
	if (!gr_mbuf_flow_hash_is_valid(m))
		gr_mbuf_flow_hash_set(m, gr_mbuf_flow_hash(m, GR_MBUF_FLOW_HASH_L3_L4));
	return m->hash.rss;
}

// Same as gr_mbuf_flow_hash_get() for packets whose data starts with an IPv4
// or IPv6 header. eth_type must match that header.
static inline uint32_t gr_mbuf_flow_hash_get_l3(struct rte_mbuf *m, rte_be16_t eth_type) {
	if (!gr_mbuf_flow_hash_is_valid(m))
		gr_mbuf_flow_hash_set(m, gr_mbuf_flow_hash_l3(m, eth_type));
	return m->hash.rss;
}
