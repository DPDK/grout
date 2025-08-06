// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_ip4.h>
#include <gr_net_types.h>
#include <gr_nh_control.h>

#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_rcu_qsbr.h>

#include <stdint.h>

static inline struct nexthop *nh4_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	// XXX: should we scope ip4 nh lookup based on rfc3927 ?
	return nexthop_lookup(GR_AF_IP4, vrf_id, GR_IFACE_ID_UNDEF, &ip);
}

void nh4_unreachable_cb(struct rte_mbuf *m);
void arp_probe_input_cb(struct rte_mbuf *m);

struct nexthop *rib4_lookup(uint16_t vrf_id, ip4_addr_t ip);
struct nexthop *rib4_lookup_exact(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen);
int rib4_insert(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	struct nexthop *nh
);
int rib4_delete(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen, gr_nh_type_t nh_type);
void rib4_cleanup(struct nexthop *);

typedef void (*rib4_iter_cb_t)(
	uint16_t vrf_id,
	ip4_addr_t,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	const struct nexthop *,
	void *priv
);
void rib4_iter(uint16_t vrf_id, rib4_iter_cb_t cb, void *priv);

// get the default address for a given interface
struct nexthop *addr4_get_preferred(uint16_t iface_id, ip4_addr_t dst);
// get all addresses for a given interface
struct hoplist *addr4_get_all(uint16_t iface_id);

struct rib4_stats {
	uint32_t total_routes;
	uint32_t by_origin[_GR_NH_ORIGIN_COUNT];
};

// Get route stats for IPv4 (exposed for telemetry)
const struct rib4_stats *rib4_get_stats(uint16_t vrf_id);
