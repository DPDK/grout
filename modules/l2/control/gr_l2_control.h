// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_module.h>
#include <gr_net_types.h>

#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

#include <stdbool.h>
#include <stdint.h>

// Forward declarations for optional feature subsystems.
struct rstp_bridge;
struct mcast_snooping;
struct vlan_filtering;
struct lldp_config;
struct storm_control;

// Per-core bridge statistics, indexed by [bridge_id][lcore_id].
struct bridge_stats {
	uint64_t unicast_fwd;
	uint64_t broadcast_fwd;
	uint64_t multicast_fwd;
	uint64_t flood_fwd;
	uint64_t no_fdb_drop;
	uint64_t hairpin_drop;
	uint64_t iface_down_drop;
	uint64_t learn_ok;
	uint64_t learn_update;
	uint64_t learn_fail;
	uint64_t learn_skip;
	uint64_t learn_limit_bridge;
	uint64_t learn_limit_iface;
	uint64_t learn_shutdown;
	uint64_t mac_moves;
	uint64_t rstp_blocking_drop;
	uint64_t rstp_learn_skip;
};

// Per-core FDB statistics, indexed by [bridge_id][lcore_id].
struct fdb_stats {
	uint64_t lookup_hit;
	uint64_t lookup_miss;
	uint64_t entries_aged;
};

#define L2_MAX_BRIDGES 256

extern struct bridge_stats l2_bridge_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];
extern struct fdb_stats l2_fdb_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];

static inline struct bridge_stats *bridge_get_stats(uint16_t bridge_id, uint16_t lcore_id) {
	if (bridge_id >= L2_MAX_BRIDGES)
		return NULL;
	return &l2_bridge_stats[bridge_id][lcore_id];
}

static inline struct fdb_stats *fdb_get_stats(uint16_t bridge_id, uint16_t lcore_id) {
	if (bridge_id >= L2_MAX_BRIDGES)
		return NULL;
	return &l2_fdb_stats[bridge_id][lcore_id];
}

// Per-interface security configuration.
struct iface_security {
	uint32_t max_macs; // 0 = unlimited (default)
	bool shutdown_on_violation;
	bool is_shutdown;
};

// Per-interface dynamic MAC count per core.
struct iface_mac_count {
	uint32_t dynamic_macs;
};

#define L2_MAX_IFACES 1024

extern struct iface_security l2_iface_security[L2_MAX_IFACES];
extern struct iface_mac_count l2_iface_mac_counts[L2_MAX_IFACES][RTE_MAX_LCORE];

// Interface security accessor functions.
uint32_t iface_get_max_macs(uint16_t iface_id);
bool iface_get_shutdown_on_violation(uint16_t iface_id);
bool iface_is_shutdown(uint16_t iface_id);
void iface_shutdown_violation(uint16_t iface_id);
void iface_increment_mac_count(uint16_t iface_id, uint16_t lcore_id);
void iface_decrement_mac_count(uint16_t iface_id, uint16_t lcore_id);
uint32_t iface_get_total_macs(uint16_t iface_id);

// Internal bridge info structure.
GR_IFACE_INFO(GR_IFACE_TYPE_BRIDGE, iface_info_bridge, {
	BASE(__gr_iface_info_bridge_base);

	struct iface *members[GR_BRIDGE_MAX_MEMBERS];

	// Optional feature subsystems, NULL when disabled.
	struct rstp_bridge *rstp;
	struct mcast_snooping *mcast_snoop;
	struct vlan_filtering *vlan_filter;
	struct lldp_config *lldp;
});

// Feature accessor helpers.
struct rstp_bridge *bridge_get_rstp(const struct iface *bridge);
struct mcast_snooping *bridge_get_mcast_snooping(const struct iface *bridge);
struct vlan_filtering *bridge_get_vlan_filtering(const struct iface *bridge);
struct lldp_config *bridge_get_lldp_config(const struct iface *bridge);

// RSTP helpers for datapath.
bool rstp_port_is_forwarding(const struct iface *bridge, uint16_t iface_id);
bool rstp_port_is_learning(const struct iface *bridge, uint16_t iface_id);

// Lookup a FDB entry from a MAC address and VLAN
const struct gr_fdb_entry *
fdb_lookup(uint16_t bridge_id, const struct rte_ether_addr *, uint16_t vlan_id);

// Learn a new FDB entry or refresh its last_seen timestamp.
void fdb_learn(
	uint16_t bridge_id,
	uint16_t iface_id,
	const struct rte_ether_addr *,
	uint16_t vlan_id,
	ip4_addr_t vtep
);

// Delete all FDB entries referencing the provided interface.
void fdb_purge_iface(uint16_t iface_id);

// Delete all FDB entries referencing the provided bridge.
void fdb_purge_bridge(uint16_t bridge_id);

struct vxlan_template {
	struct rte_ipv4_hdr ip;
	struct rte_udp_hdr udp;
	struct rte_vxlan_hdr vxlan;
};

GR_IFACE_INFO(GR_IFACE_TYPE_VXLAN, iface_info_vxlan, {
	BASE(gr_iface_info_vxlan);

	struct vxlan_template template;

	uint16_t n_flood_vteps;
	ip4_addr_t *flood_vteps;
});

struct iface *vxlan_get_iface(rte_be32_t vni, uint16_t encap_vrf_id);

// Flood list type callbacks, registered per gr_flood_t.
struct flood_type_ops {
	gr_flood_type_t type;
	int (*add)(const struct gr_flood_entry *, bool exist_ok);
	int (*del)(const struct gr_flood_entry *, bool missing_ok);
	int (*list)(uint16_t vrf_id, struct api_ctx *);
};

void flood_type_register(const struct flood_type_ops *);

#define VXLAN_FLAGS_VNI RTE_BE32(GR_BIT32(27))

static inline rte_be32_t vxlan_decode_vni(rte_be32_t vx_vni) {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	return (rte_be32_t)((uint32_t)vx_vni >> 8);
#else
	return (rte_be32_t)((uint32_t)(vx_vni & RTE_BE32(0xffffff00)) << 8);
#endif
}

static inline rte_be32_t vxlan_encode_vni(uint32_t vni) {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	return (rte_be32_t)((uint32_t)vni << 8);
#else
	return (rte_be32_t)((uint32_t)rte_cpu_to_be_32(vni) >> 8);
#endif
}
