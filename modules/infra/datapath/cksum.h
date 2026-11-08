// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Red Hat, Inc.

#pragma once

#include "mbuf.h"

#include <rte_mbuf.h>

#define GR_CKSUM_IP_BAD RTE_MBUF_F_RX_IP_CKSUM_BAD
#define GR_CKSUM_IP_GOOD RTE_MBUF_F_RX_IP_CKSUM_GOOD
#define GR_CKSUM_IP_MASK (GR_CKSUM_IP_BAD | GR_CKSUM_IP_GOOD)

#define GR_CKSUM_L4_BAD RTE_MBUF_F_RX_L4_CKSUM_BAD
#define GR_CKSUM_L4_GOOD RTE_MBUF_F_RX_L4_CKSUM_GOOD
#define GR_CKSUM_L4_MASK (GR_CKSUM_L4_BAD | GR_CKSUM_L4_GOOD)

#define GR_CKSUM_MASK (GR_CKSUM_IP_MASK | GR_CKSUM_L4_MASK)

static inline bool gr_cksum_ip_good(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_IP_MASK) == GR_CKSUM_IP_GOOD;
}

static inline bool gr_cksum_ip_unknown(const struct rte_mbuf *m) {
	return !(m->ol_flags & GR_CKSUM_IP_MASK);
}

static inline void gr_cksum_ip_set_good(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_IP_BAD;
	m->ol_flags |= GR_CKSUM_IP_GOOD;
}

static inline bool gr_cksum_l4_bad(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_L4_MASK) == GR_CKSUM_L4_BAD;
}

static inline bool gr_cksum_l4_partial(const struct rte_mbuf *m) {
	return (m->ol_flags & GR_CKSUM_L4_MASK) == GR_CKSUM_L4_MASK;
}

static inline bool gr_cksum_l4_valid(const struct rte_mbuf *m) {
	return !!(m->ol_flags & GR_CKSUM_L4_GOOD);
}

static inline void gr_cksum_l4_set_good(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_L4_BAD;
	m->ol_flags |= GR_CKSUM_L4_GOOD;
}

static inline void gr_cksum_l4_set_partial(struct rte_mbuf *m) {
	m->ol_flags |= GR_CKSUM_L4_MASK;
}

static inline void gr_cksum_reset(struct rte_mbuf *m) {
	m->ol_flags &= ~GR_CKSUM_MASK;
}

static inline void gr_cksum_tunnel_push(struct rte_mbuf *m, uint64_t tunnel_type) {
	gr_cksum_reset(m);
	gr_mbuf_tunnel_set(m, tunnel_type);
}

static inline void gr_cksum_tunnel_pop(struct rte_mbuf *m) {
	gr_mbuf_tunnel_clear(m);
	gr_cksum_reset(m);
}
