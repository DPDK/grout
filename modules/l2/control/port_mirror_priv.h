// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#pragma once

#include <gr_l2_control.h>
#include <gr_vec.h>

#include <rte_ether.h>
#include <rte_mbuf.h>

#include <stdbool.h>
#include <stdint.h>

#define MAX_MIRROR_SESSIONS 8
#define MAX_SOURCE_PORTS 16

struct mirror_filter {
	bool enabled;
	gr_vec uint16_t *vlans;
	uint16_t ether_type;
	struct rte_ether_addr src_mac;
	struct rte_ether_addr dst_mac;
	bool src_mac_set;
	bool dst_mac_set;
};

struct mirror_session {
	uint16_t session_id;
	bool enabled;
	gr_vec uint16_t *source_ports;
	uint16_t dest_port;
	uint8_t direction;
	struct mirror_filter filter;
	bool is_rspan;
	uint16_t rspan_vlan;
};

struct port_mirroring {
	struct mirror_session sessions[MAX_MIRROR_SESSIONS];
	uint16_t num_sessions;
};

struct mirror_stats {
	uint64_t packets_mirrored;
	uint64_t packets_dropped;
	uint64_t filter_matched;
	uint64_t filter_rejected;
	uint64_t clone_failed;
};

extern struct port_mirroring port_mirrors[L2_MAX_BRIDGES];
extern struct mirror_stats mirror_stats_arr[L2_MAX_BRIDGES][RTE_MAX_LCORE];

// Control plane.
int port_mirror_session_set(
	uint16_t bridge_id,
	uint16_t session_id,
	bool enabled,
	const uint16_t *source_ports,
	uint16_t num_sources,
	uint16_t dest_port,
	uint8_t direction,
	bool is_rspan,
	uint16_t rspan_vlan
);

int port_mirror_session_get(
	uint16_t bridge_id,
	uint16_t session_id,
	struct mirror_session *session
);

int port_mirror_session_del(uint16_t bridge_id, uint16_t session_id);

int port_mirror_filter_set(
	uint16_t bridge_id,
	uint16_t session_id,
	bool enabled,
	const uint16_t *vlans,
	uint16_t num_vlans,
	uint16_t ether_type,
	const struct rte_ether_addr *src_mac,
	const struct rte_ether_addr *dst_mac
);

struct mirror_stats *port_mirror_get_stats(uint16_t lcore_id, uint16_t bridge_id);

// Datapath helpers.
bool port_mirror_should_mirror(
	uint16_t bridge_id,
	uint16_t iface_id,
	uint8_t direction,
	uint16_t *session_ids,
	uint16_t *num_sessions
);

bool port_mirror_filter_match(const struct mirror_filter *filter, const struct rte_mbuf *mbuf);

static inline bool port_mirror_is_source(const struct mirror_session *s, uint16_t iface_id) {
	if (s == NULL || s->source_ports == NULL)
		return false;
	for (uint16_t i = 0; i < gr_vec_len(s->source_ports); i++) {
		if (s->source_ports[i] == iface_id)
			return true;
	}
	return false;
}
