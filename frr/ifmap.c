// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Christophe Fontaine, Red Hat

#include "ifmap.h"

#include <gr_infra.h>

DEFINE_MGROUP(GROUT, "Grout plugin memory");
DEFINE_MTYPE(GROUT, GROUT_MEM, "Grout plugin memory");

PREDECL_HASH(zg_grout_to_frr); // grout_ifindex -> frr ifindex
PREDECL_HASH(zg_frr_to_grout); // frr ifindex -> grout_ifindex

struct ifindex_mapping {
	struct zg_grout_to_frr_item forward_item;
	struct zg_frr_to_grout_item reverse_item;
	uint16_t grout_ifindex;
	ifindex_t frr_ifindex;
};

static int zg_grout_to_frr_cmp(const struct ifindex_mapping *a, const struct ifindex_mapping *b) {
	return numcmp(a->grout_ifindex, b->grout_ifindex);
}

static uint32_t zg_grout_to_frr_hash(const struct ifindex_mapping *mapping) {
	return mapping->grout_ifindex;
}

DECLARE_HASH(
	zg_grout_to_frr,
	struct ifindex_mapping,
	forward_item,
	zg_grout_to_frr_cmp,
	zg_grout_to_frr_hash
);

static int zg_frr_to_grout_cmp(const struct ifindex_mapping *a, const struct ifindex_mapping *b) {
	return numcmp(a->frr_ifindex, b->frr_ifindex);
}

static uint32_t zg_frr_to_grout_hash(const struct ifindex_mapping *mapping) {
	return mapping->frr_ifindex;
}

DECLARE_HASH(
	zg_frr_to_grout,
	struct ifindex_mapping,
	reverse_item,
	zg_frr_to_grout_cmp,
	zg_frr_to_grout_hash
);

// Global hash table instances
static struct zg_grout_to_frr_head zg_grout_to_frr = INIT_HASH(zg_grout_to_frr);
static struct zg_frr_to_grout_head zg_frr_to_grout = INIT_HASH(zg_frr_to_grout);

// Add bidirectional mapping
bool zg_ifmap_add(uint16_t grout_ifindex, ifindex_t frr_ifindex) {
	struct ifindex_mapping *mapping = XCALLOC(MTYPE_GROUT_MEM, sizeof(*mapping));
	mapping->grout_ifindex = grout_ifindex;
	mapping->frr_ifindex = frr_ifindex;

	// Add to both hash tables
	struct ifindex_mapping *existing_forward = zg_grout_to_frr_add(&zg_grout_to_frr, mapping);
	if (existing_forward && existing_forward != mapping) {
		XFREE(MTYPE_GROUT_MEM, mapping);
		return false; // Duplicate grout_ifindex
	}

	struct ifindex_mapping *existing_reverse = zg_frr_to_grout_add(&zg_frr_to_grout, mapping);
	if (existing_reverse && existing_reverse != mapping) {
		zg_grout_to_frr_del(&zg_grout_to_frr, mapping);
		XFREE(MTYPE_GROUT_MEM, mapping);
		return false; // Duplicate frr_ifindex
	}

	return true;
}

ifindex_t zg_ifindex_to_frr(uint16_t grout_ifindex) {
	struct ifindex_mapping key = {.grout_ifindex = grout_ifindex};
	struct ifindex_mapping *found = zg_grout_to_frr_find(&zg_grout_to_frr, &key);
	return found ? found->frr_ifindex : IFINDEX_INTERNAL;
}

uint16_t zg_ifindex_to_grout(ifindex_t frr_ifindex) {
	struct ifindex_mapping key = {.frr_ifindex = frr_ifindex};
	struct ifindex_mapping *found = zg_frr_to_grout_find(&zg_frr_to_grout, &key);
	return found ? found->grout_ifindex : GR_IFACE_ID_UNDEF;
}

bool zg_ifmap_del(uint16_t grout_ifindex) {
	struct ifindex_mapping key = {.grout_ifindex = grout_ifindex};
	struct ifindex_mapping *found = zg_grout_to_frr_find(&zg_grout_to_frr, &key);
	if (!found)
		return false;

	zg_grout_to_frr_del(&zg_grout_to_frr, found);
	zg_frr_to_grout_del(&zg_frr_to_grout, found);
	XFREE(MTYPE_GROUT_MEM, found);
	return true;
}

vrf_id_t zg_vrf_to_frr(uint16_t gr_vrf_id) {
	if (gr_vrf_id == GR_VRF_DEFAULT_ID)
		return VRF_DEFAULT;
	return zg_ifindex_to_frr(gr_vrf_id);
}

uint16_t zg_vrf_to_grout(vrf_id_t frr_vrf_id) {
	if (frr_vrf_id == VRF_DEFAULT)
		return GR_VRF_DEFAULT_ID;
	return zg_ifindex_to_grout(frr_vrf_id);
}

void zg_ifmap_init(void) {
	zg_grout_to_frr_init(&zg_grout_to_frr);
	zg_frr_to_grout_init(&zg_frr_to_grout);
}
