// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Christophe Fontaine, Red Hat

#include "if_map.h"

#include <gr_infra.h>

#include <lib/frr_pthread.h>

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
static pthread_mutex_t ifindex_mtx = PTHREAD_MUTEX_INITIALIZER;

// Add bidirectional mapping
bool add_ifindex_mapping(uint16_t grout_ifindex, ifindex_t frr_ifindex) {
	struct ifindex_mapping *mapping = XCALLOC(MTYPE_GROUT_MEM, sizeof(*mapping));
	mapping->grout_ifindex = grout_ifindex;
	mapping->frr_ifindex = frr_ifindex;

	frr_with_mutex(&ifindex_mtx) {
		struct ifindex_mapping *existing_forward = grout_to_frr_add(
			&grout_to_frr_mappings, mapping
		);
		if (existing_forward && existing_forward != mapping) {
			XFREE(MTYPE_GROUT_MEM, mapping);
			return false;
		}

		struct ifindex_mapping *existing_reverse = frr_to_grout_add(
			&frr_to_grout_mappings, mapping
		);
		if (existing_reverse && existing_reverse != mapping) {
			grout_to_frr_del(&grout_to_frr_mappings, mapping);
			XFREE(MTYPE_GROUT_MEM, mapping);
			return false;
		}
	}

	return true;
}

ifindex_t ifindex_grout_to_frr(uint16_t grout_ifindex) {
	struct ifindex_mapping key = {.grout_ifindex = grout_ifindex};
	ifindex_t ret = IFINDEX_INTERNAL;

	frr_with_mutex(&ifindex_mtx) {
		struct ifindex_mapping *found = grout_to_frr_find(&grout_to_frr_mappings, &key);
		if (found)
			ret = found->frr_ifindex;
	}

	return ret;
}

uint16_t ifindex_frr_to_grout(ifindex_t frr_ifindex) {
	struct ifindex_mapping key = {.frr_ifindex = frr_ifindex};
	uint16_t ret = GR_IFACE_ID_UNDEF;

	frr_with_mutex(&ifindex_mtx) {
		struct ifindex_mapping *found = frr_to_grout_find(&frr_to_grout_mappings, &key);
		if (found)
			ret = found->grout_ifindex;
	}

	return ret;
}

bool remove_mapping_by_grout_ifindex(uint16_t grout_ifindex) {
	struct ifindex_mapping key = {.grout_ifindex = grout_ifindex};
	struct ifindex_mapping *found = NULL;

	frr_with_mutex(&ifindex_mtx) {
		found = grout_to_frr_find(&grout_to_frr_mappings, &key);
		if (!found)
			return false;

		grout_to_frr_del(&grout_to_frr_mappings, found);
		frr_to_grout_del(&frr_to_grout_mappings, found);
	}

	XFREE(MTYPE_GROUT_MEM, found);
	return true;
}

vrf_id_t vrf_grout_to_frr(uint16_t gr_vrf_id) {
	if (gr_vrf_id == GR_VRF_DEFAULT_ID)
		return VRF_DEFAULT;
	return ifindex_grout_to_frr(gr_vrf_id);
}

uint16_t vrf_frr_to_grout(vrf_id_t frr_vrf_id) {
	if (frr_vrf_id == VRF_DEFAULT)
		return GR_VRF_DEFAULT_ID;
	return ifindex_frr_to_grout(frr_vrf_id);
}

void clear_ifindex_mappings(void) {
	struct ifindex_mapping *m;

	frr_with_mutex(&ifindex_mtx) {
		frr_each_safe(grout_to_frr, &grout_to_frr_mappings, m) {
			grout_to_frr_del(&grout_to_frr_mappings, m);
			frr_to_grout_del(&frr_to_grout_mappings, m);
			XFREE(MTYPE_GROUT_MEM, m);
		}
	}
}

// Initialize the mapping tables
void init_ifindex_mappings(void) {
	grout_to_frr_init(&grout_to_frr_mappings);
	frr_to_grout_init(&frr_to_grout_mappings);
}
