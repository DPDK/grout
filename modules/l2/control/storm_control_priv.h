// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#pragma once

#include <gr_l2_control.h>

#include <rte_meter.h>

#include <stdbool.h>
#include <stdint.h>

// Traffic types for storm control.
enum storm_traffic_type {
	STORM_TRAFFIC_BROADCAST = 0,
	STORM_TRAFFIC_MULTICAST,
	STORM_TRAFFIC_UNKNOWN_UC,
};

// Per-interface configuration.
struct storm_control_config {
	bool enabled;
	uint64_t bcast_rate_kbps;
	uint64_t mcast_rate_kbps;
	uint64_t unknown_uc_rate_kbps;
	bool use_pps;
	bool shutdown_on_violation;
	uint8_t violation_threshold;
};

// Per-core metering state for each interface.
struct storm_control_state {
	struct rte_meter_trtcm bcast_meter;
	struct rte_meter_trtcm_profile bcast_profile;
	struct rte_meter_trtcm mcast_meter;
	struct rte_meter_trtcm_profile mcast_profile;
	struct rte_meter_trtcm unknown_uc_meter;
	struct rte_meter_trtcm_profile unknown_uc_profile;
	uint64_t last_update_tsc;
	uint8_t bcast_violations;
	uint8_t mcast_violations;
	uint8_t unknown_uc_violations;
	bool is_shutdown;
};

// Per-core statistics.
struct storm_control_stats {
	uint64_t bcast_passed;
	uint64_t bcast_dropped;
	uint64_t mcast_passed;
	uint64_t mcast_dropped;
	uint64_t unknown_uc_passed;
	uint64_t unknown_uc_dropped;
	uint64_t shutdown_events;
};

extern struct storm_control_config storm_control_configs[L2_MAX_IFACES];
extern struct storm_control_state storm_control_states[L2_MAX_IFACES][RTE_MAX_LCORE];
extern struct storm_control_stats storm_control_stats_arr[L2_MAX_IFACES][RTE_MAX_LCORE];

static inline struct storm_control_stats *
storm_control_get_stats(uint16_t lcore_id, uint16_t iface_id) {
	if (iface_id >= L2_MAX_IFACES || lcore_id >= RTE_MAX_LCORE)
		return NULL;
	return &storm_control_stats_arr[iface_id][lcore_id];
}

// Configuration.
int storm_control_set_config(
	uint16_t iface_id,
	bool enabled,
	uint64_t bcast_rate_kbps,
	uint64_t mcast_rate_kbps,
	uint64_t unknown_uc_rate_kbps,
	bool use_pps,
	bool shutdown_on_violation,
	uint8_t violation_threshold
);

int storm_control_get_config(uint16_t iface_id, struct storm_control_config *cfg);
int storm_control_reenable_interface(uint16_t iface_id);
int storm_control_init_meters(uint16_t iface_id, uint16_t lcore_id);

// Datapath metering (returns true if packet should be forwarded).
bool storm_control_meter_packet(
	uint16_t iface_id,
	uint16_t lcore_id,
	enum storm_traffic_type traffic_type,
	uint32_t packet_len
);

// Mockable meter check wrapper.
enum rte_color storm_control_meter_check(
	struct rte_meter_trtcm *m,
	struct rte_meter_trtcm_profile *p,
	uint64_t time,
	uint32_t pkt_len
);
