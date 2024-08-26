// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP4_CONTROL
#define _GR_IP4_CONTROL

#include <gr_ip4.h>
#include <gr_net_types.h>

#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>

#include <stdint.h>

struct __rte_cache_aligned nexthop {
	gr_ip4_nh_flags_t flags;
	struct rte_ether_addr lladdr;
	uint16_t vrf_id;
	uint16_t iface_id;
	ip4_addr_t ip;
	uint64_t last_request, last_reply;
	uint32_t ref_count; // number of routes referencing this nexthop
	uint8_t prefixlen;
	uint8_t ucast_probes : 4, bcast_probes : 4;
	rte_spinlock_t lock;
	// packets waiting for ARP resolution
	uint16_t held_pkts_num;
	struct rte_mbuf *held_pkts_head;
	struct rte_mbuf *held_pkts_tail;
};

#define IP4_HOPLIST_MAX_SIZE 8

struct hoplist {
	unsigned count;
	struct nexthop *nh[IP4_HOPLIST_MAX_SIZE];
};

// Max number of packets to hold per next hop waiting for resolution (default: 256).
#define IP4_NH_MAX_HELD_PKTS 256
// Reachable next hop lifetime after last ARP reply received (default: 20 min).
#define IP4_NH_LIFETIME_REACHABLE (20 * 60)
// Unreachable next hop lifetime after last unreplied ARP request was sent (default: 1 min).
#define IP4_NH_LIFETIME_UNREACHABLE 60
// Max number of unicast ARP probes to send after IP4_NH_LIFETIME_REACHABLE.
#define IP4_NH_UCAST_PROBES 3
// Max number of broadcast ARP probes to send after unicast probes failed.
#define IP4_NH_BCAST_PROBES 3

// XXX: why not 1337, eh?
#define IP4_MAX_NEXT_HOPS (1 << 16)
#define IP4_MAX_ROUTES (1 << 16)
#define IP4_MAX_VRFS 256

struct nexthop *ip4_nexthop_lookup(uint16_t vrf_id, ip4_addr_t ip);
struct nexthop *ip4_nexthop_new(uint16_t vrf_id, uint16_t iface_id, ip4_addr_t ip);
void ip4_nexthop_incref(struct nexthop *);
void ip4_nexthop_decref(struct nexthop *);

int ip4_route_insert(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen, struct nexthop *);
int ip4_route_delete(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen);
struct nexthop *ip4_route_lookup(uint16_t vrf_id, ip4_addr_t ip);
struct nexthop *ip4_route_lookup_exact(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen);
void ip4_route_cleanup(struct nexthop *);

// get the default address for a given interface
struct nexthop *ip4_addr_get_preferred(uint16_t iface_id, ip4_addr_t dst);
// get all addresses for a given interface
struct hoplist *ip4_addr_get_all(uint16_t iface_id);

#endif
