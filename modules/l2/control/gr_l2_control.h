// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_l2.h>

#include <stdint.h>

// Internal bridge info structure.
GR_IFACE_INFO(GR_IFACE_TYPE_BRIDGE, iface_info_bridge, {
	BASE(__gr_iface_info_bridge_base);

	struct iface *members[GR_BRIDGE_MAX_MEMBERS];
});

// Lookup a FDB entry from a MAC address and VLAN
const struct gr_fdb_entry *
fdb_lookup(uint16_t bridge_id, const struct rte_ether_addr *, uint16_t vlan_id);

// Learn a new FDB entry or refresh its last_seen timestamp.
void fdb_learn(
	uint16_t bridge_id,
	uint16_t iface_id,
	const struct rte_ether_addr *,
	uint16_t vlan_id
);

// Delete all FDB entries referencing the provided interface.
void fdb_purge_iface(uint16_t iface_id);

// Delete all FDB entries referencing the provided bridge.
void fdb_purge_bridge(uint16_t bridge_id);
