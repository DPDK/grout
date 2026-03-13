// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_errno.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_net_types.h>
#include <gr_netlink.h>
#include <gr_vrf.h>

#include <rte_ethdev.h>

#include <assert.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

static const struct vrf_fib_ops *fib_ops[256];

void vrf_fib_ops_register(addr_family_t af, const struct vrf_fib_ops *ops) {
	if (!gr_af_valid(af))
		ABORT("invalid af value %hhu", af);
	if (ops == NULL || ops->init == NULL || ops->reconfig == NULL || ops->fini == NULL)
		ABORT("invalid vrf fib ops");
	if (fib_ops[af] != NULL)
		ABORT("duplicate vrf fib ops %s", gr_af_name(af));
	fib_ops[af] = ops;
}

static struct gr_iface_info_vrf_fib *vrf_fib_conf(struct iface_info_vrf *vrf, addr_family_t af) {
	if (af == GR_AF_IP4)
		return &vrf->ipv4;
	if (af == GR_AF_IP6)
		return &vrf->ipv6;
	return NULL;
}

static const struct gr_iface_info_vrf_fib *
vrf_fib_api(const struct gr_iface_info_vrf *info, addr_family_t af) {
	if (af == GR_AF_IP4)
		return &info->ipv4;
	if (af == GR_AF_IP6)
		return &info->ipv6;
	return NULL;
}

struct iface *get_vrf_iface(uint16_t vrf_id) {
	struct iface *iface = iface_from_id(vrf_id);
	if (iface == NULL || iface->type != GR_IFACE_TYPE_VRF)
		return errno_set_null(ENONET);

	return iface;
}

#define GR_VRF_IFALIAS "Grout control plane vrf"

static int netlink_create_vrf_and_enslave(
	const char *vrf_name,
	uint32_t vrf_table,
	uint32_t loop_ifindex,
	uint32_t *vrf_ifindex
) {
	char ifalias[IFALIASZ];
	char kind[IFNAMSIZ];
	uint32_t ifindex;
	int ret;

	// Check for a stale VRF device left behind by a previous crash.
	ifindex = if_nametoindex(vrf_name);
	if (ifindex != 0) {
		ret = netlink_link_get_kind(vrf_name, kind, sizeof(kind));
		if (ret < 0 || strcmp(kind, "vrf") != 0)
			return errno_set(EEXIST);

		ret = netlink_get_ifalias(vrf_name, ifalias, sizeof(ifalias));
		if (ret < 0 || strcmp(ifalias, GR_VRF_IFALIAS) != 0)
			return errno_set(EEXIST);

		LOG(WARNING, "deleting stale VRF device %s (ifindex %u)", vrf_name, ifindex);
		ret = netlink_link_del_iface(ifindex);
		if (ret < 0)
			return ret;
	}

	ret = netlink_link_add_vrf(vrf_name, vrf_table);
	if (ret < 0)
		return ret;

	*vrf_ifindex = ret;

	ret = netlink_set_ifalias(*vrf_ifindex, GR_VRF_IFALIAS);
	if (ret < 0)
		return ret;

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

static int iface_vrf_init(struct iface *iface, const void *api_info) {
	struct iface_info_vrf *vrf = iface_info_vrf(iface);
	const struct gr_iface_info_vrf *info = api_info;
	unsigned af;

	// VRF's vrf_id is its own iface_id (VRF identifier)
	iface->vrf_id = iface->id;
	vrf->ref_count = 0;

	if (iface_loopback_create(iface) < 0)
		return -errno;

	if (netlink_vrf_add(iface) < 0)
		goto netlink_fail;

	for (af = 0; af < ARRAY_DIM(fib_ops); af++) {
		if (fib_ops[af] == NULL)
			continue;
		// info is NULL when the default VRF is created internally.
		const struct gr_iface_info_vrf_fib *api = info ? vrf_fib_api(info, af) : NULL;
		if (api != NULL)
			*vrf_fib_conf(vrf, af) = *api;
		if (fib_ops[af]->init(iface) < 0)
			goto fib_fail;
	}

	iface->flags = GR_IFACE_F_UP;
	iface->state = GR_IFACE_S_RUNNING;
	iface->speed = RTE_ETH_SPEED_NUM_10G;
	return 0;

fib_fail:
	// Only fini AFs that completed init; the failing one cleans up itself.
	for (unsigned i = 0; i < af; i++) {
		if (fib_ops[i] == NULL)
			continue;
		fib_ops[i]->fini(iface);
	}
	netlink_vrf_del(iface);
netlink_fail:
	iface_loopback_destroy(iface);
	return -errno;
}

static int iface_vrf_fini(struct iface *iface) {
	for (unsigned af = 0; af < ARRAY_DIM(fib_ops); af++)
		if (fib_ops[af] != NULL)
			fib_ops[af]->fini(iface);

	if (netlink_vrf_del(iface) < 0)
		return -errno;

	return iface_loopback_destroy(iface);
}

static int iface_vrf_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *conf,
	const void *api_info
) {
	struct iface_info_vrf *vrf = iface_info_vrf(iface);
	const struct gr_iface_info_vrf *info = api_info;

	if (set_attrs & ~(GR_IFACE_SET_NAME | GR_VRF_SET_FIB))
		return errno_set(EOPNOTSUPP);

	if (set_attrs & GR_IFACE_SET_NAME) {
		uint32_t ifindex;

		// Default VRF: TUN device uses the VRF name directly.
		// Non-default VRFs: kernel VRF device uses the VRF name.
		if (iface->id == GR_VRF_DEFAULT_ID)
			ifindex = iface->cp_id;
		else
			ifindex = vrf->vrf_ifindex;

		if (netlink_link_set_name(ifindex, conf->name) < 0)
			return -errno;
	}

	if (set_attrs & GR_VRF_SET_FIB) {
		for (unsigned af = 0; af < ARRAY_DIM(fib_ops); af++) {
			const struct gr_iface_info_vrf_fib *api;
			struct gr_iface_info_vrf_fib *fib_conf;
			struct gr_iface_info_vrf_fib old;

			api = vrf_fib_api(info, af);
			if (api == NULL)
				continue;
			if (api->max_routes == 0 && api->num_tbl8 == 0)
				continue;

			assert(fib_ops[af] != NULL);

			fib_conf = vrf_fib_conf(vrf, af);
			old = *fib_conf;

			if (api->max_routes) {
				fib_conf->max_routes = api->max_routes;
				if (!api->num_tbl8)
					fib_conf->num_tbl8 = 0;
			}
			if (api->num_tbl8)
				fib_conf->num_tbl8 = api->num_tbl8;

			if (fib_conf->max_routes == old.max_routes
			    && fib_conf->num_tbl8 == old.num_tbl8)
				continue;

			if (fib_ops[af]->reconfig(iface) < 0) {
				*fib_conf = old;
				return -errno;
			}

			LOG(INFO,
			    "resized %s FIB VRF %s(%u) max_routes %u -> %u num_tbl8 %u -> %u",
			    gr_af_name(af),
			    iface->name,
			    iface->id,
			    old.max_routes,
			    fib_conf->max_routes,
			    old.num_tbl8,
			    fib_conf->num_tbl8);
		}
	}

	return 0;
}

static void iface_vrf_to_api(void *info, const struct iface *iface) {
	const struct iface_info_vrf *vrf = iface_info_vrf(iface);
	struct gr_iface_info_vrf *api = info;

	*api = vrf->base;
}

static struct iface_type iface_type_vrf = {
	.id = GR_IFACE_TYPE_VRF,
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
