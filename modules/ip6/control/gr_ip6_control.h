// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP6_CONTROL
#define _GR_IP6_CONTROL

#include <gr_ip6.h>
#include <gr_net_types.h>

#include <rte_ether.h>
#include <rte_fib6.h>
#include <rte_hash.h>
#include <rte_ip6.h>
#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>

#include <stdint.h>

struct __rte_cache_aligned nexthop6 {
	gr_ip6_nh_flags_t flags;
	struct rte_ether_addr lladdr;
	uint16_t vrf_id;
	uint16_t iface_id;
	struct rte_ipv6_addr ip;
	uint32_t ref_count; // number of routes (or interfaces) referencing this nexthop
	uint8_t prefixlen;
};

#define IP6_HOPLIST_MAX_SIZE 16

struct hoplist6 {
	unsigned count;
	struct nexthop6 *nh[IP6_HOPLIST_MAX_SIZE];
};

// XXX: why not 1337, eh?
#define IP6_MAX_NEXT_HOPS (1 << 16)
#define IP6_MAX_ROUTES (1 << 16)
#define IP6_MAX_VRFS 256

struct nexthop6 *ip6_nexthop_lookup(uint16_t vrf_id, const struct rte_ipv6_addr *);
struct nexthop6 *ip6_nexthop_new(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *);
void ip6_nexthop_incref(struct nexthop6 *);
void ip6_nexthop_decref(struct nexthop6 *);

int ip6_route_insert(uint16_t vrf_id, const struct rte_ipv6_addr *, uint8_t prefixlen, struct nexthop6 *);
int ip6_route_delete(uint16_t vrf_id, const struct rte_ipv6_addr *, uint8_t prefixlen);
void ip6_route_cleanup(struct nexthop6 *);
struct nexthop6 *ip6_route_lookup(uint16_t vrf_id, const struct rte_ipv6_addr *);
struct nexthop6 *
ip6_route_lookup_exact(uint16_t vrf_id, const struct rte_ipv6_addr *, uint8_t prefixlen);

#endif
