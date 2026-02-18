// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#pragma once

#include <gr_l2_control.h>

#include <stdbool.h>
#include <stdint.h>

// Maximum VLAN ID (802.1Q uses 12 bits, 0 and 4095 are reserved).
#define MAX_VLAN_ID 4094

// Bitmap size for fast VLAN membership checks (4096 VLANs / 64 bits = 64 entries).
#define VLAN_BITMAP_SIZE 64

enum port_vlan_mode {
	PORT_VLAN_MODE_ACCESS = 0, // Single untagged VLAN
	PORT_VLAN_MODE_TRUNK,      // Multiple tagged VLANs
	PORT_VLAN_MODE_HYBRID,     // Mix of tagged + native VLAN
};

struct vlan_translation {
	uint16_t ingress_outer_vlan;
	uint16_t ingress_inner_vlan;
	bool ingress_enabled;

	uint16_t egress_outer_vlan;
	uint16_t egress_inner_vlan;
	bool egress_enabled;

	bool qinq_enabled;
	uint16_t qinq_svid; // Outer S-VLAN ID for Q-in-Q
};

struct port_vlan_config {
	enum port_vlan_mode mode;
	uint16_t access_vlan;
	uint16_t native_vlan;
	uint64_t allowed_vlans[VLAN_BITMAP_SIZE]; // Bitmap for fast lookup
	bool pvid_enabled;
	struct vlan_translation translation;
};

struct vlan_filtering {
	bool enabled;
	struct port_vlan_config port_configs[L2_MAX_IFACES];
};

// Per-core statistics.
struct vlan_filter_stats {
	uint64_t ingress_filtered;
	uint64_t egress_filtered;
	uint64_t pvid_added;
	uint64_t tag_removed;
	uint64_t translated;
	uint64_t egress_translated;
	uint64_t qinq_added;
	uint64_t qinq_removed;
	uint64_t mode_access;
	uint64_t mode_trunk;
	uint64_t mode_hybrid;
};

extern struct vlan_filter_stats vlan_filter_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];

// Bitmap helpers.
static inline bool vlan_is_allowed(const uint64_t *bitmap, uint16_t vlan_id) {
	if (vlan_id > MAX_VLAN_ID)
		return false;
	return (bitmap[vlan_id / 64] & (1ULL << (vlan_id % 64))) != 0;
}

static inline void vlan_allow(uint64_t *bitmap, uint16_t vlan_id) {
	if (vlan_id <= MAX_VLAN_ID)
		bitmap[vlan_id / 64] |= (1ULL << (vlan_id % 64));
}

static inline void vlan_disallow(uint64_t *bitmap, uint16_t vlan_id) {
	if (vlan_id <= MAX_VLAN_ID)
		bitmap[vlan_id / 64] &= ~(1ULL << (vlan_id % 64));
}

static inline void vlan_clear_all(uint64_t *bitmap) {
	for (int i = 0; i < VLAN_BITMAP_SIZE; i++)
		bitmap[i] = 0;
}

static inline void vlan_allow_all(uint64_t *bitmap) {
	for (int i = 0; i < VLAN_BITMAP_SIZE; i++)
		bitmap[i] = ~0ULL;
}

// Bridge integration.
struct vlan_filtering *vlan_filtering_alloc(void);
void vlan_filtering_free(struct vlan_filtering *vf);

// Port configuration.
int vlan_port_set_access(struct vlan_filtering *vf, uint16_t iface_id, uint16_t vlan_id);

int vlan_port_set_trunk(
	struct vlan_filtering *vf,
	uint16_t iface_id,
	uint16_t native_vlan,
	const uint16_t *allowed_vlans,
	uint16_t num_vlans
);

int vlan_port_set_translation(
	struct vlan_filtering *vf,
	uint16_t iface_id,
	uint16_t outer_vlan,
	uint16_t inner_vlan
);

int vlan_port_clear_translation(struct vlan_filtering *vf, uint16_t iface_id);

int vlan_port_set_egress_translation(
	struct vlan_filtering *vf,
	uint16_t iface_id,
	uint16_t outer_vlan,
	uint16_t inner_vlan
);

int vlan_port_set_qinq(struct vlan_filtering *vf, uint16_t iface_id, uint16_t svid);
int vlan_port_clear_qinq(struct vlan_filtering *vf, uint16_t iface_id);

// Ingress/egress filtering.
bool vlan_ingress_check(
	const struct vlan_filtering *vf,
	uint16_t iface_id,
	uint16_t vlan_id,
	bool is_tagged
);

bool vlan_egress_check(
	const struct vlan_filtering *vf,
	uint16_t iface_id,
	uint16_t vlan_id,
	bool *should_untag
);
