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

#include <stdint.h>

static inline struct nexthop *
nh6_new(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip) {
	return nexthop_new(GR_NH_IPV6, vrf_id, iface_id, ip);
}

static inline struct nexthop *
nh6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip) {
	return nexthop_lookup(GR_NH_IPV6, vrf_id, iface_id, ip);
}

void nh6_unreachable_cb(struct rte_mbuf *m);
void ndp_probe_input_cb(struct rte_mbuf *m);
void ndp_router_sollicit_input_cb(struct rte_mbuf *m);

int rib6_insert(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *, uint8_t prefixlen, struct nexthop *);
int rib6_delete(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *,
	uint8_t prefixlen
);
void rib6_cleanup(struct nexthop *);
struct nexthop *rib6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *);

// get the default address for a given interface
struct nexthop *addr6_get_preferred(uint16_t iface_id, const struct rte_ipv6_addr *);
// get all addresses for a given interface
struct hoplist *addr6_get_all(uint16_t iface_id);
// determine if the given interface is member of the provided multicast address group
struct nexthop *mcast6_get_member(uint16_t iface_id, const struct rte_ipv6_addr *mcast);

#endif
