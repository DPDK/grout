// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_rcu.h>
#include <gr_vlan.h>

#include <event2/event.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>

#include <string.h>

struct vlan_key {
	uint16_t parent_id;
	uint16_t vlan_id;
};

static struct rte_hash *vlan_hash;

struct iface *vlan_get_iface(uint16_t parent_id, uint16_t vlan_id) {
	void *data;

	if (rte_hash_lookup_data(vlan_hash, &(struct vlan_key) {parent_id, vlan_id}, &data) < 0)
		return NULL;

	return data;
}

static int iface_vlan_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *,
	const void *api_info
) {
	struct iface_info_vlan *cur = iface_info_vlan(iface);
	const struct gr_iface_info_vlan *next = api_info;
	bool reconfig = set_attrs != IFACE_SET_ALL;
	struct iface *cur_parent, *next_parent;
	int ret;

	if (reconfig) {
		if ((cur_parent = iface_from_id(cur->parent_id)) == NULL)
			return -errno;
		if (set_attrs & GR_VLAN_SET_MAC) {
			// reconfig, *not initial config*
			// remove previous mac filter (ignore errors)
			iface_del_eth_addr(cur->parent_id, &cur->mac);
		}
	} else {
		cur_parent = NULL;
	}

	if (set_attrs & (GR_VLAN_SET_PARENT | GR_VLAN_SET_VLAN)) {
		struct vlan_key next_key = {next->parent_id, next->vlan_id};

		if ((next_parent = iface_from_id(next->parent_id)) == NULL)
			return -errno;

		if (rte_hash_lookup(vlan_hash, &next_key) >= 0)
			return errno_set(EADDRINUSE);

		if (reconfig) {
			// reconfig, *not initial config*
			struct vlan_key cur_key = {cur->parent_id, cur->vlan_id};

			rte_hash_del_key(vlan_hash, &cur_key);
			iface_del_subinterface(cur_parent, iface);

			// remove previous vlan filter (ignore errors)
			iface_del_vlan(cur->parent_id, cur->vlan_id);
		}

		if (iface_add_vlan(next->parent_id, next->vlan_id) < 0)
			return -errno;
		cur->parent_id = next->parent_id;
		cur->vlan_id = next->vlan_id;
		iface_add_subinterface(next_parent, iface);
		iface->state = next_parent->state;
		iface->mtu = next_parent->mtu;

		if ((ret = rte_hash_add_key_data(vlan_hash, &next_key, iface)) < 0)
			return errno_log(-ret, "rte_hash_add_key_data");
	}

	if (set_attrs & GR_VLAN_SET_MAC) {
		if (rte_is_zero_ether_addr(&next->mac)) {
			if ((ret = iface_get_eth_addr(next->parent_id, &cur->mac)) < 0)
				return ret;
		} else {
			if ((ret = iface_add_eth_addr(next->parent_id, &next->mac)) < 0)
				return ret;
			cur->mac = next->mac;
		}
	}

	return 0;
}

static int iface_vlan_fini(struct iface *iface) {
	struct iface_info_vlan *vlan = iface_info_vlan(iface);
	struct iface *parent = iface_from_id(vlan->parent_id);
	int ret, status = 0;

	rte_hash_del_key(vlan_hash, &(struct vlan_key) {vlan->parent_id, vlan->vlan_id});

	if ((ret = iface_del_vlan(vlan->parent_id, vlan->vlan_id)) < 0)
		status = ret;

	if ((ret = iface_del_eth_addr(vlan->parent_id, &vlan->mac)) < 0)
		status = status ?: ret;

	iface_del_subinterface(parent, iface);

	return status;
}

static int iface_vlan_init(struct iface *iface, const void *api_info) {
	int ret;

	ret = iface_vlan_reconfig(iface, IFACE_SET_ALL, NULL, api_info);
	if (ret < 0) {
		iface_vlan_fini(iface);
		errno = -ret;
	}

	return ret;
}

static int iface_vlan_get_eth_addr(const struct iface *iface, struct rte_ether_addr *mac) {
	const struct iface_info_vlan *vlan = iface_info_vlan(iface);
	*mac = vlan->mac;
	return 0;
}

static int iface_vlan_add_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	const struct iface_info_vlan *vlan = iface_info_vlan(iface);

	if (mac == NULL || !rte_is_multicast_ether_addr(mac))
		return errno_set(EINVAL);

	return iface_add_eth_addr(vlan->parent_id, mac);
}

static int iface_vlan_del_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	const struct iface_info_vlan *vlan = iface_info_vlan(iface);

	if (mac == NULL || !rte_is_multicast_ether_addr(mac))
		return errno_set(EINVAL);

	return iface_del_eth_addr(vlan->parent_id, mac);
}

static void vlan_to_api(void *info, const struct iface *iface) {
	const struct iface_info_vlan *vlan = iface_info_vlan(iface);
	struct gr_iface_info_vlan *api = info;

	*api = vlan->base;
}

static struct iface_type iface_type_vlan = {
	.id = GR_IFACE_TYPE_VLAN,
	.name = "vlan",
	.pub_size = sizeof(struct gr_iface_info_vlan),
	.priv_size = sizeof(struct iface_info_vlan),
	.init = iface_vlan_init,
	.reconfig = iface_vlan_reconfig,
	.fini = iface_vlan_fini,
	.get_eth_addr = iface_vlan_get_eth_addr,
	.add_eth_addr = iface_vlan_add_eth_addr,
	.del_eth_addr = iface_vlan_del_eth_addr,
	.to_api = vlan_to_api,
};

static void vlan_init(struct event_base *) {
	struct rte_hash_parameters params = {
		.name = "vlan",
		.entries = MAX_IFACES,
		.key_len = sizeof(struct vlan_key),
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	vlan_hash = rte_hash_create(&params);
	if (vlan_hash == NULL)
		ABORT("rte_hash_create(vlan)");

	struct rte_hash_rcu_config rcu_config = {
		.v = gr_datapath_rcu(), .mode = RTE_HASH_QSBR_MODE_SYNC
	};
	rte_hash_rcu_qsbr_add(vlan_hash, &rcu_config);
}

static void vlan_fini(struct event_base *) {
	rte_hash_free(vlan_hash);
	vlan_hash = NULL;
}

static struct gr_module vlan_module = {
	.name = "vlan",
	.depends_on = "rcu",
	.init = vlan_init,
	.fini = vlan_fini,
};

RTE_INIT(vlan_constructor) {
	gr_register_module(&vlan_module);
	iface_type_register(&iface_type_vlan);
}
