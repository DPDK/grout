// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#pragma once

#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_vec.h>

#include <rte_ether.h>

#include <stdbool.h>
#include <stdint.h>

struct ipsg_config {
	uint16_t bridge_id;
	bool enabled;
	bool verify_source;
	bool log_violations;
};

struct ipsg_stats {
	uint64_t ipv4_packets;
	uint64_t valid_packets;
	uint64_t drops_no_binding;
	uint64_t drops_ip_mismatch;
};

extern struct ipsg_stats ipsg_stats_table[L2_MAX_BRIDGES][RTE_MAX_LCORE];

struct ipsg_config *ipsg_config_get(uint16_t bridge_id);
