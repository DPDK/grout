// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_port.h>
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

static int get_parent_port_id(uint16_t parent_id, uint16_t *port_id) {
	const struct iface *parent = iface_from_id(parent_id);
	const struct iface_info_port *port;

	if (parent == NULL)
		return -errno;
	if (parent->type_id != GR_IFACE_TYPE_PORT)
		return errno_set(EMEDIUMTYPE);

	port = (const struct iface_info_port *)parent->info;
	*port_id = port->port_id;

	return 0;
}

static int iface_vlan_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *conf,
	const void *api_info
) {
	struct iface_info_vlan *cur = (struct iface_info_vlan *)iface->info;
	const struct gr_iface_info_vlan *next = api_info;
	bool reconfig = set_attrs != IFACE_SET_ALL;
	struct iface *cur_parent, *next_parent;
	struct iface_type *parent_type;
	int ret;

	if (reconfig) {
		if ((cur_parent = iface_from_id(cur->parent_id)) == NULL)
			return -errno;
	} else {
		cur_parent = NULL;
	}
	if ((next_parent = iface_from_id(next->parent_id)) == NULL)
		return -errno;

	parent_type = iface_type_get(next_parent->type_id);

	if (set_attrs & (GR_VLAN_SET_PARENT | GR_VLAN_SET_VLAN)) {
		struct vlan_key next_key = {next->parent_id, next->vlan_id};
		uint16_t next_port_id = RTE_MAX_ETHPORTS;

		if (get_parent_port_id(next->parent_id, &next_port_id) < 0)
			return -errno;

		if (rte_hash_lookup(vlan_hash, &next_key) >= 0)
			return errno_set(EADDRINUSE);

		if (reconfig) {
			// reconfig, *not initial config*
			struct vlan_key cur_key = {cur->parent_id, cur->vlan_id};
			uint16_t cur_port_id = RTE_MAX_ETHPORTS;

			rte_hash_del_key(vlan_hash, &cur_key);
			iface_del_subinterface(cur_parent, iface);

			if (get_parent_port_id(cur->parent_id, &cur_port_id) < 0)
				return -errno;

			// remove previous vlan filter (ignore errors)
			if ((ret = rte_eth_dev_vlan_filter(cur_port_id, cur->vlan_id, false)) < 0)
				errno_log(-ret, "rte_eth_dev_vlan_filter disable");
		}

		if ((ret = rte_eth_dev_vlan_filter(next_port_id, next->vlan_id, true)) < 0) {
			errno_log(-ret, "rte_eth_dev_vlan_filter enable");
			if (ret != -ENOTSUP && ret != -ENOSYS)
				return errno_set(-ret);
		}
		cur->parent_id = next->parent_id;
		cur->vlan_id = next->vlan_id;
		iface_add_subinterface(next_parent, iface);

		if ((ret = rte_hash_add_key_data(vlan_hash, &next_key, iface)) < 0)
			return errno_log(-ret, "rte_hash_add_key_data");
	}

	if (set_attrs & GR_VLAN_SET_MAC) {
		if (reconfig) {
			// reconfig, *not initial config*
			// remove previous mac filter (ignore errors)
			parent_type->del_eth_addr(cur_parent, &cur->mac);
		}
		if ((ret = parent_type->add_eth_addr(next_parent, &next->mac)) < 0)
			return ret;
		cur->mac = next->mac;
	}

	if (set_attrs & GR_IFACE_SET_FLAGS)
		iface->flags = conf->flags;
	if (set_attrs & GR_IFACE_SET_MTU)
		iface->mtu = conf->mtu ? conf->mtu : iface_from_id(cur->parent_id)->mtu;
	if (set_attrs & GR_IFACE_SET_VRF)
		iface->vrf_id = conf->vrf_id;

	gr_event_push(IFACE_EVENT_POST_RECONFIG, iface);

	return 0;
}

static int iface_vlan_fini(struct iface *iface) {
	struct iface_info_vlan *vlan = (struct iface_info_vlan *)iface->info;
	struct iface *parent = iface_from_id(vlan->parent_id);
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct iface_type *parent_type;
	int ret, status = 0;

	if (get_parent_port_id(vlan->parent_id, &port_id) < 0)
		return -errno;

	parent_type = iface_type_get(parent->type_id);

	rte_hash_del_key(vlan_hash, &(struct vlan_key) {vlan->parent_id, vlan->vlan_id});

	if ((ret = rte_eth_dev_vlan_filter(port_id, vlan->vlan_id, false)) < 0)
		errno_log(-ret, "rte_eth_dev_vlan_filter disable");
	if (status == 0 && ret < 0) {
		switch (errno) {
		case ENOSYS:
		case EOPNOTSUPP:
			break;
		default:
			status = ret;
		}
	}

	ret = parent_type->del_eth_addr(parent, &vlan->mac);
	if (status == 0 && ret < 0) {
		switch (errno) {
		case ENOSYS:
		case EOPNOTSUPP:
			break;
		default:
			status = ret;
		}
	}

	iface_del_subinterface(parent, iface);

	return status;
}

static int iface_vlan_init(struct iface *iface, const void *api_info) {
	const struct gr_iface conf = {
		.flags = iface->flags, .mtu = iface->mtu, .vrf_id = iface->vrf_id
	};
	int ret;

	ret = iface_vlan_reconfig(iface, IFACE_SET_ALL, &conf, api_info);
	if (ret < 0) {
		iface_vlan_fini(iface);
		errno = -ret;
	}

	return ret;
}

static int iface_vlan_get_eth_addr(const struct iface *iface, struct rte_ether_addr *mac) {
	const struct iface_info_vlan *vlan = (const struct iface_info_vlan *)iface->info;
	*mac = vlan->mac;
	return 0;
}

static int iface_vlan_add_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	const struct iface_info_vlan *vlan = (const struct iface_info_vlan *)iface->info;

	if (mac == NULL || !rte_is_multicast_ether_addr(mac))
		return errno_set(EINVAL);

	return iface_add_eth_addr(vlan->parent_id, mac);
}

static int iface_vlan_del_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	const struct iface_info_vlan *vlan = (const struct iface_info_vlan *)iface->info;

	if (mac == NULL || !rte_is_multicast_ether_addr(mac))
		return errno_set(EINVAL);

	return iface_del_eth_addr(vlan->parent_id, mac);
}

static void vlan_to_api(void *info, const struct iface *iface) {
	const struct iface_info_vlan *vlan = (const struct iface_info_vlan *)iface->info;
	struct gr_iface_info_vlan *api = info;

	api->parent_id = vlan->parent_id;
	api->vlan_id = vlan->vlan_id;
	api->mac = vlan->mac;
}

static struct iface_type iface_type_vlan = {
	.id = GR_IFACE_TYPE_VLAN,
	.name = "vlan",
	.info_size = sizeof(struct iface_info_vlan),
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
}

static void vlan_fini(struct event_base *) {
	rte_hash_free(vlan_hash);
	vlan_hash = NULL;
}

static struct gr_module vlan_module = {
	.name = "vlan",
	.init = vlan_init,
	.fini = vlan_fini,
	.fini_prio = 1000,
};

static void port_event(uint32_t event, const void *obj) {
	const struct iface *iface = obj;
	struct iface_info_vlan *info;
	struct iface *vlan = NULL;

	if (iface->type_id != GR_IFACE_TYPE_PORT)
		return;

	while ((vlan = iface_next(GR_IFACE_TYPE_VLAN, vlan)) != NULL) {
		info = (struct iface_info_vlan *)vlan->info;
		if (info->parent_id == iface->id) {
			if (event == IFACE_EVENT_STATUS_UP) {
				vlan->flags |= GR_IFACE_F_UP;
				vlan->state |= GR_IFACE_S_RUNNING;
			} else {
				vlan->flags &= ~GR_IFACE_F_UP;
				vlan->state &= ~GR_IFACE_S_RUNNING;
			}
			gr_event_push(event, vlan);
		}
	}
}

static struct gr_event_subscription port_event_sub = {
	.callback = port_event,
	.ev_count = 2,
	.ev_types = {IFACE_EVENT_STATUS_UP, IFACE_EVENT_STATUS_DOWN},
};

RTE_INIT(vlan_constructor) {
	gr_register_module(&vlan_module);
	iface_type_register(&iface_type_vlan);
	gr_event_subscribe(&port_event_sub);
}
