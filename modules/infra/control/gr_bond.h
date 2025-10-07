// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_vec.h>

#include <stdint.h>

#define MEMBERS_MAX_LEN ARRAY_DIM(((struct gr_iface_info_bond *)0)->members)

struct bond_member {
	const struct iface *iface;
};

GR_IFACE_INFO(GR_IFACE_TYPE_BOND, iface_info_bond, {
	gr_bond_mode_t mode;
	struct rte_ether_addr mac;

	uint8_t primary_member;
	uint8_t active_member; // Active member index (for active-backup mode)
	uint8_t n_members;
	struct bond_member members[MEMBERS_MAX_LEN];

	gr_vec struct rte_ether_addr *extra_macs;
});
