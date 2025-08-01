// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_module.h>
#include <gr_string.h>
#include <gr_vec.h>

#include <vrf_priv.h>

struct vrf_info {
	int ref_count;
	struct iface *iface;
};

// we have the same number of VRFs for IP4 and IP6
static struct vrf_info vrfs[MAX_VRFS];

struct iface *get_vrf_iface(uint16_t vrf_id) {
	return vrfs[vrf_id].iface;
}

void vrf_incref(uint16_t vrf_id) {
	if (vrf_id >= MAX_VRFS)
		return;

	if (++vrfs[vrf_id].ref_count == 1)
		vrfs[vrf_id].iface = iface_kernel_create(vrf_id);
}

void vrf_decref(uint16_t vrf_id) {
	if (vrf_id >= MAX_VRFS)
		return;

	if (--vrfs[vrf_id].ref_count == 0) {
		iface_kernel_delete(vrf_id);
		vrfs[vrf_id].iface = NULL;
	}
}
