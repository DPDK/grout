// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_errno.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_loopback.h>
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

bool vrf_is_default(const struct iface *iface) {
	if (iface->type != GR_IFACE_TYPE_VRF)
		return false;

	return iface_info_vrf(iface)->default_vrf;
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

static uint32_t iface_to_table_id(const struct iface *iface) {
	if (vrf_is_default(iface))
		return RT_TABLE_MAIN;

	// Reserved values for table_id are 0, 252, 253, 254 and 255.
	// Since we may have more than 252 VRFs, use an arbitrary value greater than 255.
	return iface->id + 1000;
}

static void netlink_vrf_add(struct vrf_info *vrf, const struct iface *loop_iface) {
	uint32_t table_id = iface_to_table_id(loop_iface);
	uint16_t vrf_id = loop_iface->vrf_id;
	int ret;

	// Only create kernel VRF device for non-default VRFs
	if (!vrf_is_default(loop_iface)) {
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
		return errno_set(EINVAL);
	}

	netlink_vrf_add(vrf, loop_iface);

	vrf->iface = loop_iface;
	vrf->ref_count = 0;

	return 0;
}

static void netlink_vrf_del(struct vrf_info *vrf) {
	const struct iface *loop_iface = vrf->iface;
	uint32_t table_id;
	int ret;

	table_id = iface_to_table_id(loop_iface);
	if (!vrf_is_default(loop_iface)) {
		ret = netlink_delete_vrf_and_unslave(vrf->vrf_ifindex, loop_iface->cp_id);
		if (ret < 0)
			LOG(WARNING,
			    "delete vrf %s (id %u) failed: %s",
			    loop_iface->name,
			    loop_iface->vrf_id,
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

// VRF interface type //////////////////////////////////////////////////////////

static int iface_vrf_init(struct iface *iface, const void *api_info) {
	const struct gr_iface_info_vrf *api = api_info;
	struct iface_info_vrf *vrf = iface_info_vrf(iface);

	// VRF's vrf_id is its own iface_id (VRF identifier)
	iface->vrf_id = iface->id;
	vrf->default_vrf = api->default_vrf;

	if (iface_loopback_create(iface) < 0)
		return -errno;

	if (vrf_add(iface) < 0) {
		iface_loopback_destroy(iface);
		return -errno;
	}

	return 0;
}

static int iface_vrf_fini(struct iface *iface) {
	vrf_del(iface->vrf_id);
	return iface_loopback_destroy(iface);
}

static void iface_vrf_to_api(void *info, const struct iface *iface) {
	struct gr_iface_info_vrf *api = info;
	const struct iface_info_vrf *priv = iface_info_vrf(iface);
	*api = priv->base;
}

static int
iface_vrf_reconfig(struct iface *, uint64_t set_attrs, const struct gr_iface *, const void *) {
	// VRF only supports name changes
	if (set_attrs & ~GR_IFACE_SET_NAME)
		return errno_set(EOPNOTSUPP);

	return 0;
}

static struct iface_type iface_type_vrf = {
	.id = GR_IFACE_TYPE_VRF,
	.name = "vrf",
	.pub_size = sizeof(struct gr_iface_info_vrf),
	.priv_size = sizeof(struct iface_info_vrf),
	.init = iface_vrf_init,
	.reconfig = iface_vrf_reconfig,
	.fini = iface_vrf_fini,
	.to_api = iface_vrf_to_api,
};

RTE_INIT(vrf_type_constructor) {
	iface_type_register(&iface_type_vrf);
	iface_name_reserve(GR_DEFAULT_VRF_NAME, false);
}
