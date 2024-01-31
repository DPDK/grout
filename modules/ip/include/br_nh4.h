// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP_NH4
#define _BR_IP_NH4

#include <br_net_types.h>

#include <rte_ether.h>
#include <rte_rcu_qsbr.h>

struct next_hop {
	struct rte_ether_addr eth_addr[2];
	uint16_t port_id;
	// number of routes with this next hop
	uint64_t ref_count;
	ip4_addr_t ip;
};

static inline struct rte_ether_addr *next_hop_eth_dst(struct next_hop *nh) {
	return &nh->eth_addr[0];
}

static inline struct rte_ether_addr *next_hop_eth_src(struct next_hop *nh) {
	return &nh->eth_addr[1];
}

#define IP4_NH_HASH_NAME "nh4"

struct rte_rcu_qsbr *br_nh4_rcu(void);

#endif
