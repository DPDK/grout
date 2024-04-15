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

struct __rte_cache_aligned next_hop {
	br_ip4_nh_flags_t flags;
	struct rte_ether_addr lladdr;
	uint16_t port_id;
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
#define MAX_NEXT_HOPS (1 << 12)
// XXX: why not 1337, eh?
#define MAX_ROUTES (1 << 16)

struct next_hop *ip4_next_hop_get(uint32_t idx);
int ip4_next_hop_lookup(ip4_addr_t ip, uint32_t *idx, struct next_hop **nh);
int ip4_next_hop_lookup_add(ip4_addr_t ip, uint32_t *idx, struct next_hop **nh);
void ip4_next_hop_incref(struct next_hop *);
void ip4_next_hop_decref(struct next_hop *);

int ip4_route_insert(ip4_addr_t ip, uint8_t prefixlen, uint32_t nh_idx, struct next_hop *);
int ip4_route_delete(ip4_addr_t ip, uint8_t prefixlen);
struct next_hop *ip4_route_lookup(ip4_addr_t ip);

struct next_hop *ip4_addr_get(uint16_t port_id);

#endif
