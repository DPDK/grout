// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_macro.h>
#include <gr_net_types.h>

#include <stdint.h>

#define GR_L2_MODULE 0xbabe

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

struct __gr_iface_info_bridge_base {
	uint16_t ageing_time; // Learned MAC ageing time in seconds (0 = default)
	gr_bridge_flags_t flags;
	struct rte_ether_addr mac; // Randomly generated if not set explicitly.
	uint16_t n_members;
};

// Info structure for GR_IFACE_TYPE_BRIDGE interfaces.
// Only port, VLAN and bond interfaces can be members.
// Members are reassigned to the default VRF when the bridge is destroyed.
struct gr_iface_info_bridge {
	BASE(__gr_iface_info_bridge_base);
	uint16_t members[GR_BRIDGE_MAX_MEMBERS]; // Interface IDs of bridge members.
};
