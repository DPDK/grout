// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP6_CONTROL
#define _GR_IP6_CONTROL

#include <gr_ip6.h>
#include <gr_net_types.h>
#include <gr_nh_control.h>

#include <rte_ether.h>
#include <rte_fib6.h>
#include <rte_hash.h>
#include <rte_ip6.h>
#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>

#include <stdint.h>

// XXX: why not 1337, eh?
#define IP6_MAX_NEXT_HOPS (1 << 16)
#define IP6_MAX_ROUTES (1 << 16)

struct nexthop *ip6_nexthop_lookup(uint16_t vrf_id, const struct rte_ipv6_addr *);
struct nexthop *ip6_nexthop_new(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *);

void ip6_nexthop_unreachable_cb(struct rte_mbuf *m);
void ndp_probe_input_cb(struct rte_mbuf *m);

int ip6_route_insert(uint16_t vrf_id, const struct rte_ipv6_addr *, uint8_t prefixlen, struct nexthop *);
int ip6_route_delete(uint16_t vrf_id, const struct rte_ipv6_addr *, uint8_t prefixlen);
void ip6_route_cleanup(struct nexthop *);
struct nexthop *ip6_route_lookup(uint16_t vrf_id, const struct rte_ipv6_addr *);
struct nexthop *
ip6_route_lookup_exact(uint16_t vrf_id, const struct rte_ipv6_addr *, uint8_t prefixlen);

// get the default address for a given interface
struct nexthop *ip6_addr_get_preferred(uint16_t iface_id, const struct rte_ipv6_addr *);
// get all addresses for a given interface
struct hoplist *ip6_addr_get_all(uint16_t iface_id);
// determine if the given interface is member of the provided multicast address group
struct nexthop *ip6_mcast_get_member(uint16_t iface_id, const struct rte_ipv6_addr *mcast);

#endif
