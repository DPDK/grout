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

int snat44_rule_add(struct iface *, ip4_addr_t match, ip4_addr_t replace);
int snat44_rule_del(struct iface *, ip4_addr_t match);

struct nexthop *rib4_lookup(uint16_t vrf_id, ip4_addr_t ip);
struct nexthop *rib4_lookup_exact(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen);
int rib4_insert(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	struct nexthop *nh
);
int rib4_delete(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen);
void rib4_cleanup(struct nexthop *);

// get the default address for a given interface
struct nexthop *addr4_get_preferred(uint16_t iface_id, ip4_addr_t dst);
// get all addresses for a given interface
struct hoplist *addr4_get_all(uint16_t iface_id);
