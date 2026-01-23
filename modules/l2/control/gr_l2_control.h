// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_nh_control.h>

#include <stdint.h>

// Internal L2 nexthop info structure with ageing timestamp.
GR_NH_TYPE_INFO(GR_NH_T_L2, nexthop_info_l2, {
	BASE(gr_nexthop_info_l2);

	clock_t last_seen; // Timestamp when last packet was seen from this MAC.
});

// Lookup a nexthop from a bridge interface ID, vlan_id and destination mac address.
struct nexthop *
nexthop_lookup_l2(uint16_t bridge_id, uint16_t vlan_id, const struct rte_ether_addr *);

// Learn a new L2 entry or refresh its last_seen timestamp.
void nexthop_learn_l2(
	uint16_t iface_id,
	uint16_t bridge_id,
	uint16_t vlan_id,
	const struct rte_ether_addr *
);

// Delete all L2 nexthops referencing the provided interface.
void nexthop_l2_purge_iface(uint16_t iface_id);

// Delete all L2 nexthops referencing the provided bridge.
void nexthop_l2_purge_bridge(uint16_t bridge_id);
