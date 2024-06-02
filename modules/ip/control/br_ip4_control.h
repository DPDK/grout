// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP4_CONTROL
#define _BR_IP4_CONTROL

#include <br_ip4.h>
#include <br_net_types.h>

#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>

#include <stdint.h>

struct __rte_cache_aligned nexthop {
	br_ip4_nh_flags_t flags;
	struct rte_ether_addr lladdr;
	uint16_t vrf_id;
	uint16_t iface_id;
	ip4_addr_t ip;
	uint8_t prefixlen;
	uint64_t last_seen;
	uint32_t ref_count;
	rte_spinlock_t lock;
	// packets waiting for ARP resolution
	uint32_t n_held_pkts;
	struct rte_mbuf *held_pkts; // linked list using br_mbuf_priv->next
};

#define IP4_NH_MAX_HELD_PKTS 8192
// XXX: why not 1337, eh?
#define MAX_NEXT_HOPS (1 << 16)
#define MAX_ROUTES (1 << 16)
#define MAX_VRFS 2048

struct nexthop *ip4_nexthop_get(uint32_t idx);
int ip4_nexthop_lookup(uint16_t vrf_id, ip4_addr_t ip, uint32_t *idx, struct nexthop **nh);
int ip4_nexthop_add(uint16_t vrf_id, ip4_addr_t ip, uint32_t *idx, struct nexthop **nh);
void ip4_nexthop_incref(struct nexthop *);
void ip4_nexthop_decref(struct nexthop *);

int ip4_route_insert(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen, uint32_t nh_idx, struct nexthop *);
int ip4_route_delete(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen);
struct nexthop *ip4_route_lookup(uint16_t vrf_id, ip4_addr_t ip);
struct nexthop *ip4_route_lookup_exact(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen);

struct nexthop *ip4_addr_get(uint16_t iface_id);

#endif
