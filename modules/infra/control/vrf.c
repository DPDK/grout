// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_module.h>
#include <gr_string.h>
#include <gr_vec.h>

#include <netlink_priv.h>
#include <vrf_priv.h>

struct vrf_info {
	int ref_count;
	struct iface *iface;
};

// we have the same number of VRFs for IP4 and IP6
static struct vrf_info vrfs[GR_MAX_VRFS];

struct iface *get_vrf_iface(uint16_t vrf_id) {
	return vrfs[vrf_id].iface;
}

void vrf_incref(uint16_t vrf_id) {
	if (vrf_id >= GR_MAX_VRFS)
		return;

	if (vrfs[vrf_id].ref_count == 0) {
		vrfs[vrf_id].iface = iface_loopback_create(vrf_id);
		if (vrfs[vrf_id].iface == NULL) {
			LOG(WARNING,
			    "loopback for vrf %u cannot be created: %s",
			    vrf_id,
			    strerror(errno));
			return;
		}
		if (netlink_add_del_vrf_rules(vrfs[vrf_id].iface->name, vrf_id, true) < 0) {
			LOG(WARNING,
			    "linux rules/routes for %s cannot be created: %s",
			    vrfs[vrf_id].iface->name,
			    strerror(errno));
		}
	}

	vrfs[vrf_id].ref_count++;
}

void vrf_decref(uint16_t vrf_id) {
	if (vrf_id >= GR_MAX_VRFS)
		return;

	if (vrfs[vrf_id].ref_count == 1) {
		if (netlink_add_del_vrf_rules(vrfs[vrf_id].iface->name, vrf_id, false) < 0) {
			LOG(WARNING,
			    "linux rules/routes for %s cannot be deleted: %s",
			    vrfs[vrf_id].iface->name,
			    strerror(errno));
		}
		if (iface_loopback_delete(vrf_id) < 0) {
			LOG(WARNING,
			    "loopback for vrf %u cannot be deleted: %s",
			    vrf_id,
			    strerror(errno));
			return;
		}
		vrfs[vrf_id].iface = NULL;
	}

	vrfs[vrf_id].ref_count--;
}
