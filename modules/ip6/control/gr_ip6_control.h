// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_control_queue.h>
#include <gr_ip6.h>
#include <gr_net_types.h>
#include <gr_nh_control.h>

#include <rte_ether.h>
#include <rte_fib6.h>
#include <rte_hash.h>
#include <rte_ip6.h>
#include <rte_rcu_qsbr.h>

#include <stdint.h>

const struct nexthop *
fib6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip);

static inline const struct rte_ipv6_addr *addr6_linklocal_scope(
	const struct rte_ipv6_addr *ip,
	struct rte_ipv6_addr *scoped_ip,
	uint16_t iface_id
) {
	if (rte_ipv6_addr_is_linklocal(ip)) {
		*scoped_ip = *ip;
		scoped_ip->a[2] = (iface_id >> 8) & 0xff;
		scoped_ip->a[3] = iface_id & 0xff;
		return scoped_ip;
	} else {
		return ip;
	}
}

static inline const struct rte_ipv6_addr *
addr6_linklocal_unscope(const struct rte_ipv6_addr *ip, struct rte_ipv6_addr *unscoped_ip) {
	if (rte_ipv6_addr_is_linklocal(ip)) {
		*unscoped_ip = *ip;
		unscoped_ip->a[2] = 0;
		unscoped_ip->a[3] = 0;
		return unscoped_ip;
	} else {
		return ip;
	}
}

static inline struct nexthop *
nh6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip) {
	return nexthop_lookup_l3(GR_AF_IP6, vrf_id, iface_id, ip);
}

void nh6_unreachable_cb(void *obj, uintptr_t priv, const struct control_queue_drain *);
void ndp_probe_input_cb(void *obj, uintptr_t priv, const struct control_queue_drain *);
void ndp_router_sollicit_input_cb(void *obj, uintptr_t priv, const struct control_queue_drain *);

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
struct nexthop *addr6_get_preferred(uint16_t iface_id, const struct rte_ipv6_addr *);
// get the link-local address for a given interface
struct nexthop *addr6_get_linklocal(uint16_t iface_id);
// get all addresses for a given interface
struct hoplist *addr6_get_all(uint16_t iface_id);
// determine if the given interface is member of the provided multicast address group
struct nexthop *mcast6_get_member(uint16_t iface_id, const struct rte_ipv6_addr *mcast);
