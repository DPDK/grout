// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_module.h>
#include <gr_string.h>
#include <gr_vec.h>

struct vrf_info {
	int ref_count;
	struct iface *iface;
};

// we have the same number of VRFs for IP4 and IP6
static struct vrf_info vrfs[MAX_VRFS];

struct iface *get_vrf_iface(uint16_t vrf_id) {
	return vrfs[vrf_id].iface;
}

static void iface_event_vrf(uint32_t event, const void *obj) {
	const struct iface *iface = obj;
	int ifaces_per_vrf[ARRAY_DIM(vrfs)] = {0};

	if (iface->type == GR_IFACE_TYPE_LOOPBACK)
		return;

	switch (event) {
	case GR_EVENT_IFACE_POST_ADD:
		if (++vrfs[iface->vrf_id].ref_count == 1)
			vrfs[iface->vrf_id].iface = iface_loopback_create(iface->vrf_id);
		break;
	case GR_EVENT_IFACE_PRE_REMOVE:
		if (--vrfs[iface->vrf_id].ref_count == 0) {
			iface_loopback_delete(iface->vrf_id);
			vrfs[iface->vrf_id].iface = NULL;
		}
		break;
	case GR_EVENT_IFACE_POST_RECONFIG:
		iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			if (iface->type == GR_IFACE_TYPE_LOOPBACK)
				continue;
			if (iface->mode == GR_IFACE_MODE_L3)
				ifaces_per_vrf[iface->vrf_id]++;
		}
		for (unsigned i = 0; i < ARRAY_DIM(vrfs); i++) {
			if (vrfs[i].ref_count > ifaces_per_vrf[i]) {
				vrfs[i].ref_count = ifaces_per_vrf[i];
				if (vrfs[i].ref_count == 0) {
					iface_loopback_delete(i);
					vrfs[i].iface = NULL;
				}
			} else if (vrfs[i].ref_count < ifaces_per_vrf[i]) {
				vrfs[i].ref_count = ifaces_per_vrf[i];
				if (vrfs[i].ref_count == 1)
					vrfs[i].iface = iface_loopback_create(i);
			}
		}
		break;
	}
}

static struct gr_event_subscription iface_event_vrf_sub = {
	.callback = iface_event_vrf,
	.ev_count = 3,
	.ev_types = {
		GR_EVENT_IFACE_POST_ADD,
		GR_EVENT_IFACE_PRE_REMOVE,
		GR_EVENT_IFACE_POST_RECONFIG,
	},
};

RTE_INIT(vrf_constructor) {
	gr_event_subscribe(&iface_event_vrf_sub);
}
