// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_errno.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_netlink.h>

#include <linux/rtnetlink.h>
#include <vrf_priv.h>

struct vrf_info {
	int ref_count;
	struct iface *iface;
	uint32_t vrf_ifindex;
};

// we have the same number of VRFs for IP4 and IP6
static struct vrf_info vrfs[GR_MAX_IFACES];

struct iface *get_vrf_iface(uint16_t vrf_id) {
	if (vrf_id == 0 || vrf_id >= GR_MAX_IFACES)
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

	ret = netlink_link_set_admin_state(*vrf_ifindex, true, false);
	if (ret < 0)
		return ret;

	ret = netlink_link_set_admin_state(loop_ifindex, true, false);
	if (ret < 0)
		return ret;

	return 0;
}

static int netlink_delete_vrf_and_unslave(uint32_t vrf_ifindex, uint32_t loop_ifindex) {
	int ret;

	ret = netlink_link_set_master(loop_ifindex, 0);
	if (ret < 0)
		return ret;

	ret = netlink_link_set_admin_state(loop_ifindex, false, false);
	if (ret < 0)
		return ret;

	return netlink_link_del_iface(vrf_ifindex);
}

static uint32_t vrf_id_to_table_id(uint16_t vrf_id) {
	if (vrf_id == GR_VRF_DEFAULT_ID)
		return RT_TABLE_MAIN;

	// Reserved values for table_id are 0, 252, 253, 254 and 255.
	// Since we may have more than 252 VRFs, use an arbitrary value greater than 255.
	return vrf_id + 1000;
}

static void netlink_vrf_add(struct vrf_info *vrf, const struct iface *loop_iface) {
	uint32_t table_id = vrf_id_to_table_id(loop_iface->vrf_id);
	uint16_t vrf_id = loop_iface->vrf_id;

	int ret;

	// Only create kernel VRF device for non-default VRFs
	if (loop_iface->id != GR_VRF_DEFAULT_ID) {
		ret = netlink_create_vrf_and_enslave(
			loop_iface->name, table_id, loop_iface->cp_id, &vrf->vrf_ifindex
		);
		if (ret < 0) {
			LOG(WARNING,
			    "create vrf %s (id %u) failed: %s",
			    loop_iface->name,
			    vrf_id,
			    strerror(errno));
			return;
		}
	}

	ret = netlink_add_route(loop_iface->cp_id, table_id);
	if (ret < 0)
		LOG(WARNING, "add route on %s failed: %s", loop_iface->name, strerror(errno));
}

int vrf_add(struct iface *loop_iface) {
	uint16_t vrf_id = loop_iface->vrf_id;
	struct vrf_info *vrf = &vrfs[vrf_id];

	if (vrf->iface != NULL) {
		LOG(WARNING, "vrf %s (id %u) already exists", loop_iface->name, vrf_id);
		return errno_set(EEXIST);
	}

	netlink_vrf_add(vrf, loop_iface);

	vrf->iface = loop_iface;
	vrf->ref_count = 0;

	return 0;
}

static void netlink_vrf_del(struct vrf_info *vrf) {
	const struct iface *loop_iface = vrf->iface;
	int ret;

	if (loop_iface->id != GR_VRF_DEFAULT_ID) {
		ret = netlink_delete_vrf_and_unslave(vrf->vrf_ifindex, loop_iface->cp_id);
		if (ret < 0)
			LOG(WARNING,
			    "delete vrf %s (id %u) failed: %s",
			    loop_iface->name,
			    loop_iface->vrf_id,
			    strerror(errno));
		vrf->vrf_ifindex = 0;
	} else {
		uint32_t table_id = vrf_id_to_table_id(loop_iface->vrf_id);

		ret = netlink_del_route(loop_iface->cp_id, table_id);
		if (ret < 0)
			LOG(WARNING,
			    "delete route on %s failed: %s",
			    loop_iface->name,
			    strerror(errno));
	}
}

int vrf_del(uint16_t vrf_id) {
	struct vrf_info *vrf;

	if (vrf_id == 0 || vrf_id >= GR_MAX_IFACES)
		return errno_set(EOVERFLOW);

	vrf = &vrfs[vrf_id];
	if (vrf->iface == NULL)
		return 0;

	netlink_vrf_del(vrf);

	vrf->iface = NULL;
	vrf->ref_count = 0;

	return 0;
}

int vrf_rename(uint16_t vrf_id, const char *new_name) {
	struct vrf_info *vrf;

	if (vrf_id == 0 || vrf_id >= GR_MAX_IFACES)
		return errno_set(EOVERFLOW);

	vrf = &vrfs[vrf_id];
	if (vrf->iface == NULL)
		return errno_set(ENONET);

	// Default VRF: TUN device uses the VRF name directly.
	// Non-default VRFs: kernel VRF device uses the VRF name.
	uint32_t ifindex;
	if (vrf_id == GR_VRF_DEFAULT_ID)
		ifindex = vrf->iface->cp_id;
	else
		ifindex = vrf->vrf_ifindex;

	return netlink_link_set_name(ifindex, new_name);
}

bool vrf_has_interfaces(uint16_t vrf_id) {
	if (vrf_id == 0 || vrf_id >= GR_MAX_IFACES)
		return false;

	return vrfs[vrf_id].ref_count > 0;
}

int vrf_incref(uint16_t vrf_id) {
	if (vrf_id == 0 || vrf_id >= GR_MAX_IFACES)
		return errno_set(EOVERFLOW);

	if (vrfs[vrf_id].iface == NULL)
		return errno_set(ENONET);

	vrfs[vrf_id].ref_count++;
	return 0;
}

void vrf_decref(uint16_t vrf_id) {
	if (vrf_id == 0 || vrf_id >= GR_MAX_IFACES)
		return;

	if (vrfs[vrf_id].ref_count > 0)
		vrfs[vrf_id].ref_count--;
}
