// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_errno.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_netlink.h>

#include <rte_ethdev.h>

#include <linux/rtnetlink.h>
#include <vrf_priv.h>

struct iface *get_vrf_iface(uint16_t vrf_id) {
	struct iface *iface = iface_from_id(vrf_id);
	if (iface == NULL || iface->type != GR_IFACE_TYPE_VRF)
		return errno_set_null(ENONET);

	return iface;
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

static int netlink_vrf_add(const struct iface *iface) {
	uint32_t table_id = vrf_id_to_table_id(iface->vrf_id);
	struct iface_info_vrf *vrf = iface_info_vrf(iface);
	int ret;

	// Only create kernel VRF device for non-default VRFs
	if (iface->id != GR_VRF_DEFAULT_ID) {
		ret = netlink_create_vrf_and_enslave(
			iface->name, table_id, iface->cp_id, &vrf->vrf_ifindex
		);
		if (ret < 0) {
			LOG(WARNING,
			    "create vrf %s (id %u) failed: %s",
			    iface->name,
			    iface->vrf_id,
			    strerror(errno));
			return ret;
		}
	}

	ret = netlink_add_route(iface->cp_id, table_id);
	if (ret < 0) {
		LOG(WARNING, "add route on %s failed: %s", iface->name, strerror(errno));
		if (iface->id != GR_VRF_DEFAULT_ID)
			netlink_delete_vrf_and_unslave(vrf->vrf_ifindex, iface->cp_id);
		return ret;
	}

	return 0;
}

static int netlink_vrf_del(const struct iface *iface) {
	struct iface_info_vrf *vrf = iface_info_vrf(iface);
	int ret;

	if (iface->id != GR_VRF_DEFAULT_ID) {
		ret = netlink_delete_vrf_and_unslave(vrf->vrf_ifindex, iface->cp_id);
		if (ret < 0) {
			LOG(WARNING,
			    "delete vrf %s (id %u) failed: %s",
			    iface->name,
			    iface->vrf_id,
			    strerror(errno));
			return ret;
		}
		vrf->vrf_ifindex = 0;
	} else {
		uint32_t table_id = vrf_id_to_table_id(iface->vrf_id);

		ret = netlink_del_route(iface->cp_id, table_id);
		if (ret < 0) {
			LOG(WARNING, "delete route on %s failed: %s", iface->name, strerror(errno));
			return ret;
		}
	}

	return 0;
}

bool vrf_has_interfaces(uint16_t vrf_id) {
	struct iface *iface = get_vrf_iface(vrf_id);
	if (iface == NULL)
		return false;

	return iface_info_vrf(iface)->ref_count > 0;
}

int vrf_incref(uint16_t vrf_id) {
	struct iface *iface = get_vrf_iface(vrf_id);
	if (iface == NULL)
		return -errno;

	iface_info_vrf(iface)->ref_count++;
	return 0;
}

void vrf_decref(uint16_t vrf_id) {
	struct iface *iface = get_vrf_iface(vrf_id);
	if (iface == NULL)
		return;

	struct iface_info_vrf *vrf = iface_info_vrf(iface);
	if (vrf->ref_count > 0)
		vrf->ref_count--;
}

// VRF interface type //////////////////////////////////////////////////////////

static int iface_vrf_init(struct iface *iface, const void *) {
	struct iface_info_vrf *vrf = iface_info_vrf(iface);

	// VRF's vrf_id is its own iface_id (VRF identifier)
	iface->vrf_id = iface->id;
	vrf->ref_count = 0;

	if (iface_loopback_create(iface) < 0)
		return -errno;

	if (netlink_vrf_add(iface) < 0) {
		iface_loopback_destroy(iface);
		return -errno;
	}

	iface->flags = GR_IFACE_F_UP;
	iface->state = GR_IFACE_S_RUNNING;
	iface->speed = RTE_ETH_SPEED_NUM_10G;
	return 0;
}

static int iface_vrf_fini(struct iface *iface) {
	if (netlink_vrf_del(iface) < 0)
		return -errno;

	return iface_loopback_destroy(iface);
}

static int iface_vrf_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *conf,
	const void *
) {
	// VRF only supports name changes
	if (set_attrs & ~GR_IFACE_SET_NAME)
		return errno_set(EOPNOTSUPP);

	if (set_attrs & GR_IFACE_SET_NAME) {
		struct iface_info_vrf *vrf = iface_info_vrf(iface);
		uint32_t ifindex;

		// Default VRF: TUN device uses the VRF name directly.
		// Non-default VRFs: kernel VRF device uses the VRF name.
		if (iface->id == GR_VRF_DEFAULT_ID)
			ifindex = iface->cp_id;
		else
			ifindex = vrf->vrf_ifindex;

		return netlink_link_set_name(ifindex, conf->name);
	}

	return 0;
}

static void iface_vrf_to_api(void * /* info */, const struct iface * /* iface */) { }

static struct iface_type iface_type_vrf = {
	.id = GR_IFACE_TYPE_VRF,
	.name = "vrf",
	.pub_size = 0,
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
