// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_control_output.h>
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
nh6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip) {
	return nexthop_lookup(GR_AF_IP6, vrf_id, iface_id, ip);
}

void nh6_unreachable_cb(struct rte_mbuf *m, const struct control_output_drain *);
void ndp_probe_input_cb(struct rte_mbuf *m, const struct control_output_drain *);
void ndp_router_sollicit_input_cb(struct rte_mbuf *m, const struct control_output_drain *);

int rib6_insert(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	struct nexthop *nh
);
int rib6_delete(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *,
	uint8_t prefixlen,
	gr_nh_type_t nh_type
);
void rib6_cleanup(struct nexthop *);
struct nexthop *rib6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *);
struct nexthop *rib6_lookup_exact(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen
);

typedef void (*rib6_iter_cb_t)(
	uint16_t vrf_id,
	const struct rte_ipv6_addr *,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	const struct nexthop *,
	void *priv
);
void rib6_iter(uint16_t vrf_id, rib6_iter_cb_t cb, void *priv);

// get the default address for a given interface
struct nexthop *addr6_get_preferred(uint16_t iface_id, const void *);
// get the link-local address for a given interface
struct nexthop *addr6_get_linklocal(uint16_t iface_id);
// get all addresses for a given interface
struct hoplist *addr6_get_all(uint16_t iface_id);
// determine if the given interface is member of the provided multicast address group
struct nexthop *mcast6_get_member(uint16_t iface_id, const struct rte_ipv6_addr *mcast);

struct rib6_stats {
	uint32_t total_routes;
	uint32_t by_origin[UINT_NUM_VALUES(gr_nh_origin_t)];
};

// Get route stats for IPv6
const struct rib6_stats *rib6_get_stats(uint16_t vrf_id);
