// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _IP4_OUTPUT_H
#define _IP4_OUTPUT_H

#include <br_net_types.h>

#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

struct ip4_output_mdyn {
	ip4_addr_t next_hop; // lookup key in ip4_next_hops
};

extern int ip4_output_mdyn_offset;

static inline struct ip4_output_mdyn *ip4_output_mdyn(struct rte_mbuf *m) {
	return RTE_MBUF_DYNFIELD(m, ip4_output_mdyn_offset, struct ip4_output_mdyn *);
}

#endif
