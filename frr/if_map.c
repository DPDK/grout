// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Christophe Fontaine, Red Hat

#include "if_map.h"

#include <gr_infra.h>

DEFINE_MGROUP(GROUT, "Grout plugin memory");
DEFINE_MTYPE(GROUT, GROUT_MEM, "Grout plugin memory");

PREDECL_HASH(grout_to_frr); // grout_ifindex -> frr ifindex
PREDECL_HASH(frr_to_grout); // frr ifindex -> grout_ifindex

struct ifindex_mapping {
	struct grout_to_frr_item forward_item;
	struct frr_to_grout_item reverse_item;
	uint16_t grout_ifindex;
	ifindex_t frr_ifindex;
};

static int grout_to_frr_cmp(const struct ifindex_mapping *a, const struct ifindex_mapping *b) {
	return numcmp(a->grout_ifindex, b->grout_ifindex);
}

static uint32_t grout_to_frr_hash(const struct ifindex_mapping *mapping) {
	return mapping->grout_ifindex;
}

DECLARE_HASH(
	grout_to_frr,
	struct ifindex_mapping,
	forward_item,
	grout_to_frr_cmp,
	grout_to_frr_hash
);

static int frr_to_grout_cmp(const struct ifindex_mapping *a, const struct ifindex_mapping *b) {
	return numcmp(a->frr_ifindex, b->frr_ifindex);
}

static uint32_t frr_to_grout_hash(const struct ifindex_mapping *mapping) {
	return mapping->frr_ifindex;
}

DECLARE_HASH(
	frr_to_grout,
	struct ifindex_mapping,
	reverse_item,
	frr_to_grout_cmp,
	frr_to_grout_hash
);

// Global hash table instances
static struct grout_to_frr_head grout_to_frr_mappings = INIT_HASH(grout_to_frr_mappings);
static struct frr_to_grout_head frr_to_grout_mappings = INIT_HASH(frr_to_grout_mappings);

// Add bidirectional mapping
bool add_ifindex_mapping(uint16_t grout_ifindex, ifindex_t frr_ifindex) {
	struct ifindex_mapping *mapping = XCALLOC(MTYPE_GROUT_MEM, sizeof(*mapping));
	mapping->grout_ifindex = grout_ifindex;
	mapping->frr_ifindex = frr_ifindex;

	// Add to both hash tables
	struct ifindex_mapping *existing_forward = grout_to_frr_add(
		&grout_to_frr_mappings, mapping
	);
	if (existing_forward && existing_forward != mapping) {
		XFREE(MTYPE_GROUT_MEM, mapping);
		return false; // Duplicate grout_ifindex
	}

	struct ifindex_mapping *existing_reverse = frr_to_grout_add(
		&frr_to_grout_mappings, mapping
	);
	if (existing_reverse && existing_reverse != mapping) {
		grout_to_frr_del(&grout_to_frr_mappings, mapping);
		XFREE(MTYPE_GROUT_MEM, mapping);
		return false; // Duplicate frr_ifindex
	}

	return true;
}

ifindex_t ifindex_grout_to_frr(uint16_t grout_ifindex) {
	struct ifindex_mapping key = {.grout_ifindex = grout_ifindex};
	struct ifindex_mapping *found = grout_to_frr_find(&grout_to_frr_mappings, &key);
	return found ? found->frr_ifindex : IFINDEX_INTERNAL;
}

uint16_t ifindex_frr_to_grout(ifindex_t frr_ifindex) {
	struct ifindex_mapping key = {.frr_ifindex = frr_ifindex};
	struct ifindex_mapping *found = frr_to_grout_find(&frr_to_grout_mappings, &key);
	return found ? found->grout_ifindex : GR_IFACE_ID_UNDEF;
}

bool remove_mapping_by_grout_ifindex(uint16_t grout_ifindex) {
	struct ifindex_mapping key = {.grout_ifindex = grout_ifindex};
	struct ifindex_mapping *found = grout_to_frr_find(&grout_to_frr_mappings, &key);
	if (!found)
		return false;

	grout_to_frr_del(&grout_to_frr_mappings, found);
	frr_to_grout_del(&frr_to_grout_mappings, found);
	XFREE(MTYPE_GROUT_MEM, found);
	return true;
}

// Initialize the mapping tables
void init_ifindex_mappings(void) {
	grout_to_frr_init(&grout_to_frr_mappings);
	frr_to_grout_init(&frr_to_grout_mappings);
}
