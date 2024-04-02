// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP4_CONTROL
#define _BR_IP4_CONTROL

#include <br_ip4_types.h>
#include <br_net_types.h>

#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_rcu_qsbr.h>

struct next_hop {
	struct rte_ether_addr eth_addr[2];
	uint16_t port_id;
	ip4_addr_t ip;
};

static inline const struct rte_ether_addr *next_hop_eth_dst(const struct next_hop *nh) {
	return &nh->eth_addr[0];
}

static inline const struct rte_ether_addr *next_hop_eth_src(const struct next_hop *nh) {
	return &nh->eth_addr[1];
}

static inline int next_hop_lookup(struct rte_hash *h, ip4_addr_t ip, struct next_hop **nh) {
	void *data = NULL;
	int ret;

	if ((ret = rte_hash_lookup_data(h, &ip, &data)) < 0)
		return ret;

	*nh = data;

	return 0;
}

#define BR_IP4_ROUTE_UNKNOWN 0

struct rte_hash *ip4_next_hops_hash_get(void);
struct rte_rcu_qsbr *ip4_next_hops_rcu_get(void);
struct rte_fib *ip4_fib_get(void);
struct rte_hash *ip4_address_hash_get(void);
struct rte_rcu_qsbr *ip4_address_rcu_get(void);

#endif
