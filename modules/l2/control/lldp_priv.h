// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#pragma once

#include <gr_l2_control.h>

#include <rte_ether.h>

#include <stdbool.h>
#include <stdint.h>

#define LLDP_ETHER_TYPE 0x88CC
#define LLDP_DEFAULT_TX_INTERVAL 30
#define LLDP_DEFAULT_TTL 120
#define LLDP_MAX_NEIGHBORS 128

// LLDP TLV types (IEEE 802.1AB).
#define LLDP_TLV_END 0
#define LLDP_TLV_CHASSIS_ID 1
#define LLDP_TLV_PORT_ID 2
#define LLDP_TLV_TTL 3
#define LLDP_TLV_PORT_DESC 4
#define LLDP_TLV_SYSTEM_NAME 5
#define LLDP_TLV_SYSTEM_DESC 6

// Chassis/Port ID subtypes.
#define LLDP_CHASSIS_ID_MAC_ADDR 4
#define LLDP_PORT_ID_IFACE_NAME 5

struct lldp_neighbor {
	uint16_t iface_id;
	uint16_t bridge_id;
	uint64_t last_update;
	uint16_t ttl;
	uint8_t chassis_id_subtype;
	uint8_t chassis_id_len;
	uint8_t chassis_id[256];
	uint8_t port_id_subtype;
	uint8_t port_id_len;
	uint8_t port_id[256];
	char port_desc[256];
	char system_name[256];
	char system_desc[256];
};

struct lldp_config {
	bool enabled;
	uint32_t tx_interval;
	uint16_t ttl;
	struct lldp_neighbor neighbors[LLDP_MAX_NEIGHBORS];
	uint16_t num_neighbors;
};

struct lldp_stats {
	uint64_t tx_frames;
	uint64_t rx_frames;
	uint64_t neighbors_added;
	uint64_t neighbors_updated;
	uint64_t neighbors_aged;
};

extern struct lldp_stats lldp_stats_arr[L2_MAX_BRIDGES][RTE_MAX_LCORE];

struct lldp_config *lldp_config_alloc(void);
void lldp_config_free(struct lldp_config *cfg);

int lldp_neighbor_add_or_update(
	struct lldp_config *cfg,
	uint16_t iface_id,
	const struct lldp_neighbor *neighbor
);

void lldp_neighbor_age_out(struct lldp_config *cfg, uint64_t now_tsc, uint64_t tsc_hz);

static inline struct lldp_stats *lldp_get_stats(uint16_t lcore_id, uint16_t bridge_id) {
	if (bridge_id >= L2_MAX_BRIDGES || lcore_id >= RTE_MAX_LCORE)
		return NULL;
	return &lldp_stats_arr[bridge_id][lcore_id];
}
