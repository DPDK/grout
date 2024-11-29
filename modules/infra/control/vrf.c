// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_iface.h>
#include <gr_ip4_control.h>
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
static struct vrf_info vrfs[IP4_MAX_VRFS];

struct iface *get_vrf_iface(uint16_t vrf_id) {
	return vrfs[vrf_id].iface;
}

static void iface_event_vrf(iface_event_t event, struct iface *iface) {
	int ifaces_per_vrf[IP4_MAX_VRFS] = {0};

	if (iface->type_id == GR_IFACE_TYPE_LOOPBACK)
		return;

	switch (event) {
	case IFACE_EVENT_POST_ADD:
		if (++vrfs[iface->vrf_id].ref_count == 1)
			vrfs[iface->vrf_id].iface = iface_loopback_create(iface->vrf_id);
		break;
	case IFACE_EVENT_PRE_REMOVE:
		if (--vrfs[iface->vrf_id].ref_count == 0) {
			iface_loopback_delete(iface->vrf_id);
			vrfs[iface->vrf_id].iface = NULL;
		}
		break;
	case IFACE_EVENT_POST_RECONFIG:
		iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			if (iface->type_id == GR_IFACE_TYPE_LOOPBACK)
				continue;
			ifaces_per_vrf[iface->vrf_id]++;
		}
		for (int i = 0; i < IP4_MAX_VRFS; i++) {
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
	default:
		break;
	}
}

static struct iface_event_handler iface_event_vrf_handler = {
	.callback = iface_event_vrf,
};

RTE_INIT(vrf_constructor) {
	iface_event_register_handler(&iface_event_vrf_handler);
}
