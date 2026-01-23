// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_bitops.h>
#include <gr_net_types.h>

#include <stdint.h>

// Info for GR_NH_T_L2 nexthops (used for bridge MAC learning).
struct gr_nexthop_info_l2 {
	uint16_t bridge_id;
	uint16_t vlan_id;
	struct rte_ether_addr mac;
};

// Bridge configuration flags.
typedef enum : uint16_t {
	GR_BRIDGE_F_NO_FLOOD = GR_BIT16(0),
	GR_BRIDGE_F_NO_LEARN = GR_BIT16(1),
} gr_bridge_flags_t;

#define GR_BRIDGE_MAX_MEMBERS 64
#define GR_BRIDGE_DEFAULT_AGEING 300

// Bridge reconfiguration attribute flags.
#define GR_BRIDGE_SET_AGEING_TIME GR_BIT64(32)
#define GR_BRIDGE_SET_FLAGS GR_BIT64(33)
#define GR_BRIDGE_SET_MAC GR_BIT64(34)

// Info structure for GR_IFACE_TYPE_BRIDGE interfaces.
struct gr_iface_info_bridge {
	uint16_t ageing_time; // Learned MAC ageing time in seconds (0 = default)
	gr_bridge_flags_t flags;
	struct rte_ether_addr mac;
	uint16_t n_members;
	uint16_t members[GR_BRIDGE_MAX_MEMBERS];
};
