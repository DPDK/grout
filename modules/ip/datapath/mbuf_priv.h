// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_MBUF_PRIV
#define _BR_MBUF_PRIV

#include <br_net_types.h>

#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

struct ip4_fwd_mbuf_priv {
	ip4_addr_t next_hop; // lookup key in ip4_next_hops
};

extern int ip4_fwd_mbuf_priv_offset;

static inline struct ip4_fwd_mbuf_priv *ip4_fwd_mbuf_priv(struct rte_mbuf *m) {
	return RTE_MBUF_DYNFIELD(m, ip4_fwd_mbuf_priv_offset, struct ip4_fwd_mbuf_priv *);
}

#endif
