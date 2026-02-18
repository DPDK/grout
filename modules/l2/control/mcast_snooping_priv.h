// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#pragma once

#include <gr_l2_control.h>
#include <gr_net_types.h>
#include <gr_vec.h>

#include <rte_ether.h>
#include <rte_hash.h>

#include <stdint.h>

#define MAX_MCAST_GROUPS 1024

// IGMP protocol constants.
#define IGMP_V2_MEMBERSHIP_REPORT 0x16
#define IGMP_V2_LEAVE_GROUP 0x17
#define IGMP_V3_MEMBERSHIP_REPORT 0x22
#define IGMP_MEMBERSHIP_QUERY 0x11

// MLD protocol constants.
#define MLD_LISTENER_QUERY 130
#define MLD_LISTENER_REPORT 131
#define MLD_LISTENER_DONE 132
#define MLDV2_LISTENER_REPORT 143

// Multicast Database entry.
struct mdb_entry {
	struct rte_ether_addr group_mac;
	union {
		ip4_addr_t ip4;
		struct rte_ipv6_addr ip6;
	} group_ip;
	gr_vec uint16_t *member_ports;
	uint64_t timestamp; // Last report (TSC)
	uint8_t ip_version;
	uint8_t is_static;
};

// Per-bridge multicast snooping configuration.
struct mcast_snooping {
	bool igmp_enabled;
	bool mld_enabled;
	uint16_t query_interval;     // Seconds (default 125)
	uint16_t max_response_time;  // 1/10 seconds (default 100 = 10s)
	bool querier_enabled;
	uint64_t last_query_tsc;
	uint32_t aging_time;         // Seconds (default 260)
	struct rte_hash *mdb;
};

// Per-core statistics.
struct mcast_snoop_stats {
	uint64_t igmp_query_rx;
	uint64_t igmp_report_rx;
	uint64_t igmp_leave_rx;
	uint64_t mld_query_rx;
	uint64_t mld_report_rx;
	uint64_t mld_done_rx;
	uint64_t mdb_lookup_hit;
	uint64_t mdb_lookup_miss;
	uint64_t mdb_add;
	uint64_t mdb_del;
	uint64_t mdb_aged;
	uint64_t selective_fwd;
	uint64_t fallback_flood;
};

extern struct mcast_snoop_stats mcast_snoop_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];

static inline struct mcast_snoop_stats *
mcast_snoop_get_stats(uint16_t lcore_id, uint16_t bridge_id) {
	if (bridge_id >= L2_MAX_BRIDGES || lcore_id >= RTE_MAX_LCORE)
		return NULL;
	return &mcast_snoop_stats[bridge_id][lcore_id];
}

// Lifecycle.
struct mcast_snooping *mcast_snooping_alloc(uint16_t bridge_id);
void mcast_snooping_free(struct mcast_snooping *mcast);

// MDB operations.
int mdb_add_entry(
	struct mcast_snooping *mcast,
	const struct rte_ether_addr *group_mac,
	const void *group_ip,
	uint8_t ip_version,
	uint16_t iface_id,
	bool is_static
);
int mdb_del_entry(
	struct mcast_snooping *mcast,
	const struct rte_ether_addr *group_mac,
	uint16_t iface_id
);
int mdb_del_port(struct mcast_snooping *mcast, uint16_t iface_id);
struct mdb_entry *mdb_lookup(
	struct mcast_snooping *mcast,
	const struct rte_ether_addr *group_mac
);

// Protocol processing.
int igmp_process_report(
	struct mcast_snooping *mcast,
	uint16_t iface_id,
	const void *group_ip,
	uint8_t ip_version
);
int igmp_process_leave(
	struct mcast_snooping *mcast,
	uint16_t iface_id,
	const void *group_ip,
	uint8_t ip_version
);

// IP-to-MAC conversion.
void mcast_ip_to_mac(const void *ip, uint8_t ip_version, struct rte_ether_addr *mac);

// Periodic callbacks.
void mdb_aging_tick(struct mcast_snooping *mcast, uint64_t now_tsc, uint64_t tsc_hz);
