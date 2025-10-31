// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_lacp.h>
#include <gr_vec.h>

#include <stdint.h>

typedef enum {
	LACP_MEMBER_FAILED = 0, // Partner not synchronized or timed out
	LACP_MEMBER_ACTIVE, // Partner synchronized, member can distribute traffic
} lacp_member_state_t;

struct lacp_info {
	lacp_member_state_t state;
	bool need_to_transmit; // Need to send immediately
	clock_t next_tx; // Next time we need to send a LACP packet
	clock_t last_rx; // Last time we received a LACP packet
	// For direct inclusion in LACP packets
	struct lacp_participant local;
	struct lacp_participant remote;
};

#define MEMBERS_MAX_LEN ARRAY_DIM(((struct gr_iface_info_bond *)0)->member_iface_ids)

GR_IFACE_INFO(GR_IFACE_TYPE_BOND, iface_info_bond, {
	gr_bond_mode_t mode;
	gr_bond_algo_t algo;
	struct rte_ether_addr mac;

	uint8_t primary_member;
	uint8_t active_member; // Active member index (for active-backup mode)
	uint8_t n_members;
	uint8_t n_active_members;

	struct iface *members[MEMBERS_MAX_LEN];
	struct iface *active_members[MEMBERS_MAX_LEN];
	struct lacp_info lacp[MEMBERS_MAX_LEN];

	gr_vec struct rte_ether_addr *extra_macs;
});
