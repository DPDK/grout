// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_ip4_control.h>
#include <gr_l2_control.h>
#include <gr_l4.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_rcu.h>
#include <gr_vrf.h>

#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include <stdatomic.h>
#include <string.h>

struct vxlan_key {
	rte_be32_t vni;
	// Use uint32_t to avoid padding issues. See ipip_key in ipip/control.c.
	uint32_t vrf_id;
};

static struct rte_hash *vxlan_hash;

struct iface *vxlan_get_iface(rte_be32_t vni, uint16_t encap_vrf_id) {
	const struct vxlan_key key = {vni, encap_vrf_id};
	void *data;

	if (rte_hash_lookup_data(vxlan_hash, &key, &data) < 0)
		return NULL;

	return data;
}

static int iface_vxlan_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *,
	const void *api_info
) {
	struct iface_info_vxlan *cur = iface_info_vxlan(iface);
	const struct vxlan_key cur_key = {rte_cpu_to_be_32(cur->vni), cur->encap_vrf_id};
	const struct gr_iface_info_vxlan *next = api_info;
	int ret;

	if (set_attrs & GR_VXLAN_SET_ENCAP_VRF) {
		uint16_t vrf = next->encap_vrf_id;
		uint16_t old = cur->encap_vrf_id;

		if (vrf == GR_VRF_ID_UNDEF)
			vrf = vrf_default_get_or_create();

		if (vrf != old && vrf_incref(vrf) < 0)
			return -errno;

		if (old != GR_VRF_ID_UNDEF)
			vrf_decref(old);

		cur->encap_vrf_id = vrf;
	}

	if (set_attrs & (GR_VXLAN_SET_VNI | GR_VXLAN_SET_ENCAP_VRF)) {
		const struct vxlan_key next_key = {rte_cpu_to_be_32(next->vni), cur->encap_vrf_id};

		if (rte_hash_lookup(vxlan_hash, &next_key) >= 0)
			return errno_set(EADDRINUSE);

		if (next->vni == 0 || next->vni > 0xffffff)
			return errno_set(ERANGE);

		rte_hash_del_key(vxlan_hash, &cur_key);

		ret = rte_hash_add_key_data(vxlan_hash, &next_key, iface);
		if (ret < 0)
			return errno_log(-ret, "rte_hash_add_key_data");

		cur->vni = next->vni;
	}

	if (set_attrs & GR_VXLAN_SET_DST_PORT) {
		uint16_t port = next->dst_port ?: RTE_VXLAN_DEFAULT_PORT;
		if (cur->dst_port != 0 && cur->dst_port != RTE_VXLAN_DEFAULT_PORT
		    && port != cur->dst_port) {
			l4_input_unalias_port(IPPROTO_UDP, rte_cpu_to_be_16(cur->dst_port));
		}
		if (port != RTE_VXLAN_DEFAULT_PORT && port != cur->dst_port) {
			l4_input_alias_port(
				IPPROTO_UDP,
				RTE_BE16(RTE_VXLAN_DEFAULT_PORT),
				rte_cpu_to_be_16(port)
			);
		}
		cur->dst_port = port;
	}

	if (set_attrs & (GR_VXLAN_SET_LOCAL | GR_VXLAN_SET_ENCAP_VRF)) {
		ip4_addr_t local = (set_attrs & GR_VXLAN_SET_LOCAL) ? next->local : cur->local;
		const struct nexthop *nh = rib4_lookup(cur->encap_vrf_id, local);
		if (nh == NULL)
			return -errno;
		if (nh->type != GR_NH_T_L3)
			return errno_set(EPROTOTYPE);

		const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
		if (!(l3->flags & GR_NH_F_LOCAL))
			return errno_set(EPROTOTYPE);

		cur->local = local;
	}

	if (set_attrs & GR_VXLAN_SET_MAC) {
		if (iface_set_eth_addr(iface, &next->mac) < 0)
			return -errno;
	}

	return 0;
}

static int iface_vxlan_fini(struct iface *iface) {
	struct iface_info_vxlan *vxlan = iface_info_vxlan(iface);
	struct gr_flood_entry entry = {
		.type = GR_FLOOD_T_VTEP,
		.vrf_id = vxlan->encap_vrf_id,
		.vtep.vni = vxlan->vni,
	};

	for (uint16_t i = 0; i < vxlan->n_flood_vteps; i++) {
		entry.vtep.addr = vxlan->flood_vteps[i];
		gr_event_push(GR_EVENT_FLOOD_DEL, &entry);
	}

	if (vxlan->encap_vrf_id != GR_VRF_ID_UNDEF)
		vrf_decref(vxlan->encap_vrf_id);

	if (vxlan->dst_port != RTE_VXLAN_DEFAULT_PORT)
		l4_input_unalias_port(IPPROTO_UDP, rte_cpu_to_be_16(vxlan->dst_port));

	rte_free(vxlan->flood_vteps);

	return 0;
}

static int iface_vxlan_init(struct iface *iface, const void *api_info) {
	struct gr_iface conf;
	int ret;

	iface->speed = RTE_ETH_SPEED_NUM_10G;
	if (iface->mtu == 0)
		iface->mtu = 1450;

	conf.base = iface->base;

	ret = iface_vxlan_reconfig(iface, IFACE_SET_ALL, &conf, api_info);
	if (ret < 0) {
		iface_vxlan_fini(iface);
		errno = -ret;
	}

	return ret;
}

static int iface_vxlan_get_eth_addr(const struct iface *iface, struct rte_ether_addr *mac) {
	const struct iface_info_vxlan *vxlan = iface_info_vxlan(iface);

	*mac = vxlan->mac;

	return 0;
}

static int iface_vxlan_set_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	struct iface_info_vxlan *vxlan = iface_info_vxlan(iface);

	if (rte_is_zero_ether_addr(mac))
		rte_eth_random_addr(vxlan->mac.addr_bytes);
	else
		vxlan->mac = *mac;

	return 0;
}

static void vxlan_to_api(void *info, const struct iface *iface) {
	const struct iface_info_vxlan *vxlan = iface_info_vxlan(iface);
	struct gr_iface_info_vxlan *api = info;
	*api = vxlan->base;
}

static const struct iface_type iface_type_vxlan = {
	.id = GR_IFACE_TYPE_VXLAN,
	.pub_size = sizeof(struct gr_iface_info_vxlan),
	.priv_size = sizeof(struct iface_info_vxlan),
	.init = iface_vxlan_init,
	.reconfig = iface_vxlan_reconfig,
	.fini = iface_vxlan_fini,
	.get_eth_addr = iface_vxlan_get_eth_addr,
	.set_eth_addr = iface_vxlan_set_eth_addr,
	.to_api = vxlan_to_api,
};

static void vxlan_pre_remove_cb(uint32_t /*ev_type*/, const void *obj) {
	const struct iface_info_vxlan *vxlan;
	const struct iface *iface = obj;

	if (iface->type != GR_IFACE_TYPE_VXLAN)
		return;

	vxlan = iface_info_vxlan(iface);
	struct vxlan_key key = {rte_cpu_to_be_32(vxlan->vni), vxlan->encap_vrf_id};
	rte_hash_del_key(vxlan_hash, &key);
}

static struct gr_event_subscription vxlan_subscription = {
	.callback = vxlan_pre_remove_cb,
	.ev_count = 1,
	.ev_types = {GR_EVENT_IFACE_PRE_REMOVE},
};

static int vtep_flood_add(const struct gr_flood_entry *entry, bool exist_ok) {
	struct iface_info_vxlan *vxlan;
	ip4_addr_t *vteps, *old_vteps;
	struct iface *iface;

	iface = vxlan_get_iface(rte_cpu_to_be_32(entry->vtep.vni), entry->vrf_id);
	if (iface == NULL)
		return errno_set(ENODEV);

	vxlan = iface_info_vxlan(iface);

	for (uint16_t i = 0; i < vxlan->n_flood_vteps; i++) {
		if (vxlan->flood_vteps[i] == entry->vtep.addr) {
			if (exist_ok)
				return 0;
			return errno_set(EEXIST);
		}
	}

	vteps = rte_calloc(__func__, vxlan->n_flood_vteps + 1, sizeof(*vteps), 0);
	if (vteps == NULL)
		return errno_set(ENOMEM);

	memcpy(vteps, vxlan->flood_vteps, vxlan->n_flood_vteps * sizeof(*vteps));
	vteps[vxlan->n_flood_vteps] = entry->vtep.addr;
	old_vteps = vxlan->flood_vteps;
	vxlan->flood_vteps = vteps;
	// ensure n_flood_vteps is incremented *after* flood_vteps is updated
	atomic_thread_fence(memory_order_release);
	vxlan->n_flood_vteps++;

	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), rte_lcore_id());
	rte_free(old_vteps);

	gr_event_push(GR_EVENT_FLOOD_ADD, entry);

	return 0;
}

static int vtep_flood_del(const struct gr_flood_entry *entry, bool missing_ok) {
	struct iface_info_vxlan *vxlan;
	struct iface *iface;

	iface = vxlan_get_iface(rte_cpu_to_be_32(entry->vtep.vni), entry->vrf_id);
	if (iface == NULL) {
		if (missing_ok)
			return 0;
		return errno_set(ENOENT);
	}

	vxlan = iface_info_vxlan(iface);

	for (uint16_t i = 0; i < vxlan->n_flood_vteps; i++) {
		if (vxlan->flood_vteps[i] == entry->vtep.addr) {
			vxlan->flood_vteps[i] = vxlan->flood_vteps[vxlan->n_flood_vteps - 1];
			vxlan->n_flood_vteps--;
			gr_event_push(GR_EVENT_FLOOD_DEL, entry);
			return 0;
		}
	}

	if (missing_ok)
		return 0;

	return errno_set(ENOENT);
}

static int vtep_flood_list(uint16_t vrf_id, struct api_ctx *ctx) {
	struct gr_flood_entry entry = {.type = GR_FLOOD_T_VTEP};
	const struct iface_info_vxlan *vxlan;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(vxlan_hash, &key, &data, &next) >= 0) {
		struct iface *iface = data;
		vxlan = iface_info_vxlan(iface);

		if (vrf_id != GR_VRF_ID_UNDEF && vxlan->encap_vrf_id != vrf_id)
			continue;

		for (uint16_t i = 0; i < vxlan->n_flood_vteps; i++) {
			entry.vrf_id = vxlan->encap_vrf_id;
			entry.vtep.vni = vxlan->vni;
			entry.vtep.addr = vxlan->flood_vteps[i];
			api_send(ctx, sizeof(entry), &entry);
		}
	}

	return 0;
}

static const struct flood_type_ops vtep_flood_ops = {
	.type = GR_FLOOD_T_VTEP,
	.add = vtep_flood_add,
	.del = vtep_flood_del,
	.list = vtep_flood_list,
};

static void vxlan_init(struct event_base *) {
	struct rte_hash_parameters params = {
		.name = "vxlan",
		.entries = GR_MAX_IFACES,
		.key_len = sizeof(struct vxlan_key),
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	vxlan_hash = rte_hash_create(&params);
	if (vxlan_hash == NULL)
		ABORT("rte_hash_create(vxlan)");

	struct rte_hash_rcu_config rcu_config = {
		.v = gr_datapath_rcu(), .mode = RTE_HASH_QSBR_MODE_SYNC
	};
	rte_hash_rcu_qsbr_add(vxlan_hash, &rcu_config);
}

static void vxlan_fini(struct event_base *) {
	rte_hash_free(vxlan_hash);
	vxlan_hash = NULL;
}

static struct gr_module vxlan_module = {
	.name = "vxlan",
	.depends_on = "rcu",
	.init = vxlan_init,
	.fini = vxlan_fini,
};

RTE_INIT(vxlan_constructor) {
	gr_register_module(&vxlan_module);
	iface_type_register(&iface_type_vxlan);
	gr_event_subscribe(&vxlan_subscription);
	flood_type_register(&vtep_flood_ops);
}
