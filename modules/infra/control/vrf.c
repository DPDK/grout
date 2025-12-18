// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_errno.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_module.h>
#include <gr_netlink.h>
#include <gr_string.h>
#include <gr_vec.h>

#include <linux/rtnetlink.h>
#include <vrf_priv.h>

struct vrf_info {
	int ref_count;
	struct iface *iface;
	uint32_t vrf_ifindex;
};

// we have the same number of VRFs for IP4 and IP6
static struct vrf_info vrfs[GR_MAX_VRFS];

struct iface *get_vrf_iface(uint16_t vrf_id) {
	if (vrf_id >= GR_MAX_VRFS)
		return errno_set_null(EOVERFLOW);
	if (vrfs[vrf_id].iface == NULL)
		return errno_set_null(ENONET);

	return vrfs[vrf_id].iface;
}

static int netlink_create_vrf_and_enslave(
	const char *vrf_name,
	uint32_t vrf_table,
	uint32_t loop_ifindex,
	uint32_t *vrf_ifindex
) {
	int ret;

	ret = netlink_link_add_vrf(vrf_name, vrf_table);
	if (ret < 0)
		return ret;

	*vrf_ifindex = ret;

	ret = netlink_link_set_master(loop_ifindex, *vrf_ifindex);
	if (ret < 0)
		return ret;

	ret = netlink_link_set_admin_state(*vrf_ifindex, true);
	if (ret < 0)
		return ret;

	ret = netlink_link_set_admin_state(loop_ifindex, true);
	if (ret < 0)
		return ret;

	return 0;
}

static int netlink_delete_vrf_and_unslave(uint32_t vrf_ifindex, uint32_t loop_ifindex) {
	int ret;

	ret = netlink_link_set_master(loop_ifindex, 0);
	if (ret < 0)
		return ret;

	ret = netlink_link_set_admin_state(loop_ifindex, false);
	if (ret < 0)
		return ret;

	return netlink_link_del_iface(vrf_ifindex);
}

static uint32_t vrf_id_to_table_id(uint16_t vrf_id) {
	if (vrf_id == 0)
		return RT_TABLE_MAIN;
	// Reserved values for table_id are 0, 252, 253, 254 and 255.
	// Since we may have more than 252 VRFs, use an arbitrary value greater than 255.
	return vrf_id + 1000;
}

static void netlink_vrf_add(struct vrf_info *vrf, const struct iface *loop_iface) {
	uint32_t table_id = vrf_id_to_table_id(loop_iface->vrf_id);
	int ret;

	if (loop_iface->vrf_id) {
		ret = netlink_create_vrf_and_enslave(
			loop_iface->name, table_id, loop_iface->cp_id, &vrf->vrf_ifindex
		);
		if (ret < 0) {
			LOG(WARNING,
			    "create vrf %u for %s failed: %s",
			    loop_iface->vrf_id,
			    loop_iface->name,
			    strerror(errno));
			return;
		}
	}

	ret = netlink_add_route(loop_iface->cp_id, table_id);
	if (ret < 0)
		LOG(WARNING, "add route on %s failed: %s", loop_iface->name, strerror(errno));
}

static void netlink_vrf_del(struct vrf_info *vrf, const struct iface *loop_iface) {
	uint32_t table_id = vrf_id_to_table_id(loop_iface->vrf_id);
	int ret;

	if (loop_iface->vrf_id) {
		ret = netlink_delete_vrf_and_unslave(vrf->vrf_ifindex, loop_iface->cp_id);
		if (ret < 0)
			LOG(WARNING,
			    "delete vrf %u for %s failed: %s",
			    loop_iface->vrf_id,
			    loop_iface->name,
			    strerror(errno));
		vrf->vrf_ifindex = 0;
	} else {
		ret = netlink_del_route(loop_iface->cp_id, table_id);
		if (ret < 0)
			LOG(WARNING,
			    "delete route on %s failed: %s",
			    loop_iface->name,
			    strerror(errno));
	}
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

		netlink_vrf_add(&vrfs[vrf_id], vrfs[vrf_id].iface);
	}

	vrfs[vrf_id].ref_count++;
}

void vrf_decref(uint16_t vrf_id) {
	if (vrf_id >= GR_MAX_VRFS)
		return;

	if (vrfs[vrf_id].ref_count == 1) {
		if (vrfs[vrf_id].iface != NULL)
			netlink_vrf_del(&vrfs[vrf_id], vrfs[vrf_id].iface);

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
