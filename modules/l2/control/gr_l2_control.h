// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_module.h>
#include <gr_net_types.h>

#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

#include <stdint.h>

// Internal bridge info structure.
GR_IFACE_INFO(GR_IFACE_TYPE_BRIDGE, iface_info_bridge, {
	BASE(__gr_iface_info_bridge_base);

	struct iface *members[GR_BRIDGE_MAX_MEMBERS];
});

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
