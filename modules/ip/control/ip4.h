// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include "control_queue.h"
#include "nexthop.h"

#include <gr_ip4.h>
#include <gr_net_types.h>

#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_rcu_qsbr.h>

#include <stdint.h>

const struct nexthop *fib4_lookup(uint16_t vrf_id, ip4_addr_t ip);

static inline struct nexthop *nh4_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	// XXX: should we scope ip4 nh lookup based on rfc3927 ?
	return nexthop_lookup_l3(GR_AF_IP4, vrf_id, GR_IFACE_ID_UNDEF, &ip);
}

void arp_probe_input_cb(void *obj, uintptr_t priv, const struct control_queue_drain *);

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

typedef int (*rib4_iter_cb_t)(
	uint16_t vrf_id,
	ip4_addr_t,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	const struct nexthop *,
	void *priv
);
struct rib4_iterator {
	unsigned count;
	unsigned max_count;
	bool skip_internal;
	rib4_iter_cb_t cb;
	void *priv;
};
int rib4_iter(uint16_t vrf_id, struct rib4_iterator *);

// get the default address for a given interface
struct nexthop *addr4_get_preferred(uint16_t iface_id, ip4_addr_t dst);
// get all addresses for a given interface
struct hoplist *addr4_get_all(uint16_t iface_id);

int addr4_add(uint16_t iface_id, ip4_addr_t ip, uint16_t prefixlen, gr_nh_origin_t);
int addr4_delete(uint16_t iface_id, ip4_addr_t ip, uint16_t prefixlen);
