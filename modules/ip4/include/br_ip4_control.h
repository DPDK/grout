// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP4_CONTROL
#define _BR_IP4_CONTROL

#include <br_net_types.h>

#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_rcu_qsbr.h>

struct next_hop {
	struct rte_ether_addr eth_addr[2];
	uint16_t port_id;
	ip4_addr_t ip;
	// number of routes with this next hop
	uint64_t ref_count;
};

static inline const struct rte_ether_addr *next_hop_eth_dst(const struct next_hop *nh) {
	return &nh->eth_addr[0];
}

static inline const struct rte_ether_addr *next_hop_eth_src(const struct next_hop *nh) {
	return &nh->eth_addr[1];
}

#define BR_IP4_ROUTE_UNKNOWN 0

struct rte_hash *ip4_next_hops_hash_get(void);
struct rte_rcu_qsbr *ip4_next_hops_rcu_get(void);
struct rte_fib *ip4_fib_get(void);

#endif
