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
	gr_nh_flags_t flags;
	struct rte_ether_addr lladdr;
	uint16_t vrf_id;
	uint16_t iface_id;
	struct rte_ipv6_addr ip;
	uint64_t last_request, last_reply;
	uint32_t ref_count; // number of routes (or interfaces) referencing this nexthop
	uint8_t prefixlen;
	uint8_t ucast_probes : 4, mcast_probes : 4;
	rte_spinlock_t lock;
	// packets waiting for NDP resolution
	uint16_t held_pkts_num;
	struct rte_mbuf *held_pkts_head;
	struct rte_mbuf *held_pkts_tail;
};

#define IP6_HOPLIST_MAX_SIZE 16

struct hoplist6 {
	unsigned count;
	struct nexthop6 *nh[IP6_HOPLIST_MAX_SIZE];
};

// Max number of packets to hold per next hop waiting for resolution (default: 256).
#define IP6_NH_MAX_HELD_PKTS 256
// Reachable next hop lifetime after last NDP reply received (default: 20 min).
#define IP6_NH_LIFETIME_REACHABLE (20 * 60)
// Unreachable next hop lifetime after last unreplied NDP request was sent (default: 1 min).
#define IP6_NH_LIFETIME_UNREACHABLE 60
// Max number of unicast NDP probes to send after IP6_NH_LIFETIME_REACHABLE.
#define IP6_NH_UCAST_PROBES 3
// Max number of multicast NDP probes to send after unicast probes failed.
#define IP6_NH_MCAST_PROBES 3

// XXX: why not 1337, eh?
#define IP6_MAX_NEXT_HOPS (1 << 16)
#define IP6_MAX_ROUTES (1 << 16)

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

// get the default address for a given interface
struct nexthop6 *ip6_addr_get_preferred(uint16_t iface_id, const struct rte_ipv6_addr *);
// get all addresses for a given interface
struct hoplist6 *ip6_addr_get_all(uint16_t iface_id);
// determine if the given interface is member of the provided multicast address group
struct nexthop6 *ip6_mcast_get_member(uint16_t iface_id, const struct rte_ipv6_addr *mcast);

#endif
