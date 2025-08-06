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

int vrf_incref(uint16_t vrf_id) {
	if (vrf_id >= MAX_VRFS)
		return errno_set(EINVAL);

	if (vrfs[vrf_id].ref_count == 0) {
		vrfs[vrf_id].iface = iface_loopback_create(vrf_id);
		if (vrfs[vrf_id].iface == NULL) {
			return errno_set(errno);
		}
	}
	vrfs[vrf_id].ref_count++;

	return 0;
}

void vrf_decref(uint16_t vrf_id) {
	if (vrf_id >= MAX_VRFS)
		return;

	if (vrfs[vrf_id].ref_count == 1) {
		int ret;

		ret = iface_loopback_delete(vrf_id);
		if (ret < 0)
			ABORT("loopback for vrf %u cannot be deleted %s", vrf_id, strerror(errno));

		assert(ret == 0);
		vrfs[vrf_id].iface = NULL;
	}

	vrfs[vrf_id].ref_count--;
	return;
}
