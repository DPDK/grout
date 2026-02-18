// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#pragma once

#include <gr_l2.h>
#include <gr_l2_control.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_meter.h>

#include <stdbool.h>
#include <stdint.h>

#define QOS_NUM_PRIORITIES 8

struct qos_queue_config {
	uint32_t rate_limit_kbps;
	uint32_t weight;
	uint32_t min_rate_kbps;
};

struct qos_port_config {
	bool enabled;
	uint8_t sched_mode; // enum gr_qos_scheduling_mode
	struct qos_queue_config queues[QOS_NUM_PRIORITIES];
	uint32_t port_rate_limit_kbps;
	bool trust_cos;
	bool trust_dscp;
	uint8_t default_priority;
	uint8_t dscp_to_cos[64];
	uint8_t cos_to_cos[8];
};

struct qos_queue_state {
	struct rte_meter_trtcm meter;
	struct rte_meter_trtcm_profile profile;
	uint32_t wrr_deficit;
	uint32_t wrr_quantum;
};

struct qos_port_state {
	struct qos_queue_state queues[QOS_NUM_PRIORITIES];
	struct rte_meter_trtcm port_meter;
	struct rte_meter_trtcm_profile port_profile;
	uint32_t last_served_queue;
};

struct qos_stats {
	uint64_t classified[QOS_NUM_PRIORITIES];
	uint64_t remarked[QOS_NUM_PRIORITIES];
	uint64_t dropped[QOS_NUM_PRIORITIES];
	uint64_t tx[QOS_NUM_PRIORITIES];
	uint64_t port_dropped;
	uint64_t no_trust;
};

extern struct qos_port_config qos_configs[L2_MAX_IFACES];
extern struct qos_port_state qos_states[L2_MAX_IFACES][RTE_MAX_LCORE];
extern struct qos_stats qos_statistics[L2_MAX_IFACES][RTE_MAX_LCORE];

// Control plane.
int qos_port_set(
	uint16_t iface_id,
	bool enabled,
	uint8_t sched_mode,
	uint32_t port_rate_kbps,
	bool trust_cos,
	bool trust_dscp,
	uint8_t default_priority
);

int qos_port_get(uint16_t iface_id, struct qos_port_config *cfg);

int qos_queue_set(
	uint16_t iface_id,
	uint8_t priority,
	uint32_t rate_limit_kbps,
	uint32_t weight,
	uint32_t min_rate_kbps
);

int qos_dscp_map_set(uint16_t iface_id, const uint8_t dscp_to_cos[64]);
int qos_cos_remap_set(uint16_t iface_id, const uint8_t cos_to_cos[8]);

struct qos_stats *qos_get_stats(uint16_t lcore_id, uint16_t iface_id);

// Datapath.
uint8_t qos_classify_packet(
	const struct qos_port_config *cfg,
	const struct rte_mbuf *mbuf,
	uint8_t *original_priority
);

enum rte_color qos_meter_check(
	struct rte_meter_trtcm *m,
	struct rte_meter_trtcm_profile *p,
	uint64_t time,
	uint32_t pkt_len
);

bool qos_meter_packet(
	uint16_t iface_id,
	uint16_t lcore_id,
	uint8_t priority,
	uint32_t packet_len
);
