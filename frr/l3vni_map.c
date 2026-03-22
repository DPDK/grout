// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Robin Jarry

#include "if_map.h"
#include "l3vni_map.h"

#include <gr_infra.h>

#include <lib/jhash.h>
#include <lib/typesafe.h>

// All functions in this file run exclusively on the dplane thread
// (grout_link_change, grout_add_nexthop, grout_neigh_update_ctx).
// No locking required.

// VRF -> VXLAN iface mapping ///////////////////////////////////////////////////

PREDECL_HASH(l3vni_hash);

struct l3vni_entry {
	struct l3vni_hash_item item;
	uint16_t vrf_id;
	uint16_t vxlan_iface_id;
};

static int l3vni_cmp(const struct l3vni_entry *a, const struct l3vni_entry *b) {
	return numcmp(a->vrf_id, b->vrf_id);
}

static uint32_t l3vni_hashfn(const struct l3vni_entry *e) {
	return e->vrf_id;
}

DECLARE_HASH(l3vni_hash, struct l3vni_entry, item, l3vni_cmp, l3vni_hashfn);
static struct l3vni_hash_head l3vni_entries = INIT_HASH(l3vni_entries);

void l3vni_set(uint16_t vrf_id, uint16_t vxlan_iface_id) {
	struct l3vni_entry *e, key = {.vrf_id = vrf_id};

	e = l3vni_hash_find(&l3vni_entries, &key);
	if (e != NULL) {
		e->vxlan_iface_id = vxlan_iface_id;
		return;
	}
	e = XCALLOC(MTYPE_GROUT_MEM, sizeof(*e));
	e->vrf_id = vrf_id;
	e->vxlan_iface_id = vxlan_iface_id;
	l3vni_hash_add(&l3vni_entries, e);
}

void l3vni_del(uint16_t vrf_id) {
	struct l3vni_entry key = {.vrf_id = vrf_id};
	struct l3vni_entry *e = l3vni_hash_find(&l3vni_entries, &key);

	if (e != NULL) {
		l3vni_hash_del(&l3vni_entries, e);
		XFREE(MTYPE_GROUT_MEM, e);
	}
}

uint16_t l3vni_get_vxlan(uint16_t vrf_id) {
	struct l3vni_entry key = {.vrf_id = vrf_id};
	struct l3vni_entry *e = l3vni_hash_find(&l3vni_entries, &key);
	return e ? e->vxlan_iface_id : GR_IFACE_ID_UNDEF;
}

// (VRF, VTEP) -> RMAC cache ///////////////////////////////////////////////////

PREDECL_HASH(rmac_hash);

struct rmac_entry {
	struct rmac_hash_item item;
	uint16_t vrf_id;
	ip4_addr_t vtep;
	struct ethaddr mac;
};

static int rmac_cmp(const struct rmac_entry *a, const struct rmac_entry *b) {
	int r = numcmp(a->vrf_id, b->vrf_id);
	return r ? r : numcmp(a->vtep, b->vtep);
}

static uint32_t rmac_hashfn(const struct rmac_entry *e) {
	return jhash_2words(e->vrf_id, e->vtep, 0);
}

DECLARE_HASH(rmac_hash, struct rmac_entry, item, rmac_cmp, rmac_hashfn);
static struct rmac_hash_head rmac_entries = INIT_HASH(rmac_entries);

void l3vni_rmac_set(uint16_t vrf_id, ip4_addr_t vtep, const struct ethaddr *mac) {
	struct rmac_entry *e, key = {.vrf_id = vrf_id, .vtep = vtep};

	e = rmac_hash_find(&rmac_entries, &key);
	if (e != NULL) {
		e->mac = *mac;
		return;
	}
	e = XCALLOC(MTYPE_GROUT_MEM, sizeof(*e));
	e->vrf_id = vrf_id;
	e->vtep = vtep;
	e->mac = *mac;
	rmac_hash_add(&rmac_entries, e);
}

void l3vni_rmac_del(uint16_t vrf_id, ip4_addr_t vtep) {
	struct rmac_entry key = {.vrf_id = vrf_id, .vtep = vtep};
	struct rmac_entry *e = rmac_hash_find(&rmac_entries, &key);

	if (e != NULL) {
		rmac_hash_del(&rmac_entries, e);
		XFREE(MTYPE_GROUT_MEM, e);
	}
}

const struct ethaddr *l3vni_rmac_get(uint16_t vrf_id, ip4_addr_t vtep) {
	struct rmac_entry key = {.vrf_id = vrf_id, .vtep = vtep};
	struct rmac_entry *e = rmac_hash_find(&rmac_entries, &key);
	return e ? &e->mac : NULL;
}
