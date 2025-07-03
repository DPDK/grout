// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_net_types.h>
#include <gr_nh_control.h>

#include <stdint.h>

// TODO: make this configurable
#define IP6_MAX_ROUTES (1 << 16)

// Only for datapath use
const struct nexthop *
fib6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip);

// Only for control plane use to update the fib
int fib6_insert(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	const struct nexthop *nh
);
int fib6_remove(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen
);

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
