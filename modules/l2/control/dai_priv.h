// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#pragma once

#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_vec.h>

#include <rte_meter.h>

#include <stdbool.h>
#include <stdint.h>

struct dai_port_config {
	uint16_t iface_id;
	bool trusted;
	uint32_t rate_limit;
	struct rte_meter_trtcm meter;
	struct rte_meter_trtcm_profile meter_profile;
};

struct dai_config {
	uint16_t bridge_id;
	bool enabled;
	bool validate_src_mac;
	bool validate_dst_mac;
	bool validate_ip;
	bool log_violations;
	struct dai_port_config *ports; // gr_vec
};

struct dai_stats {
	uint64_t arp_request_rx;
	uint64_t arp_reply_rx;
	uint64_t valid_packets;
	uint64_t drops_src_mac_mismatch;
	uint64_t drops_dst_mac_mismatch;
	uint64_t drops_ip_not_in_bindings;
	uint64_t drops_rate_limit;
	uint64_t drops_trusted_port_bypass;
};

extern struct dai_stats dai_stats_table[L2_MAX_BRIDGES][RTE_MAX_LCORE];

struct dai_config *dai_config_get(uint16_t bridge_id);
struct dai_port_config *dai_port_config_get(uint16_t bridge_id, uint16_t iface_id);
