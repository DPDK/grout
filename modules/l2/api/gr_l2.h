// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <stdint.h>

// Info for GR_NH_T_L2 nexthops (used for bridge MAC learning).
struct gr_nexthop_info_l2 {
	uint16_t bridge_id;
	uint16_t vlan_id;
	struct rte_ether_addr mac;
};
