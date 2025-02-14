// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP4_CONTROL
#define _GR_IP4_CONTROL

#include <gr_ip4.h>
#include <gr_net_types.h>
#include <gr_nh_control.h>

#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_rcu_qsbr.h>

#include <stdint.h>

static inline struct nexthop *nh4_new(uint16_t vrf_id, uint16_t iface_id, ip4_addr_t ip) {
	return nexthop_new(GR_NH_IPV4, vrf_id, iface_id, &ip);
}

static inline struct nexthop *nh4_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	// XXX: should we scope ip4 nh lookup based on rfc3927 ?
	return nexthop_lookup(GR_NH_IPV4, vrf_id, GR_IFACE_ID_UNDEF, &ip);
}

void nh4_unreachable_cb(struct rte_mbuf *m);
void arp_probe_input_cb(struct rte_mbuf *m);

struct nexthop *rib4_lookup(uint16_t vrf_id, ip4_addr_t ip);
int rib4_insert(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen, struct nexthop *);
int rib4_delete(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen);
void rib4_cleanup(struct nexthop *);

// get the default address for a given interface
struct nexthop *addr4_get_preferred(uint16_t iface_id, ip4_addr_t dst);
// get all addresses for a given interface
struct hoplist *addr4_get_all(uint16_t iface_id);

#endif
