// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ipip_priv.h"

#include <gr_event.h>
#include <gr_fib4.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_ipip.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_rcu.h>

#include <event2/event.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>

#include <string.h>

struct ipip_key {
	ip4_addr_t local;
	ip4_addr_t remote;
	// XXX: Using uint16_t causes the compiler to add 2 bytes padding at the
	// end of the structure. When the structure is initialized on the stack,
	// the padding bytes have undetermined contents.
	//
	// This structure is used to compute a hash key. In order to get
	// deterministic results, use uint32_t to store the vrf_id so that the
	// compiler does not insert any padding.
	uint32_t vrf_id;
};

static struct rte_hash *ipip_hash;

struct iface *ipip_get_iface(ip4_addr_t local, ip4_addr_t remote, uint16_t vrf_id) {
	struct ipip_key key = {local, remote, vrf_id};
	void *data;

	if (rte_hash_lookup_data(ipip_hash, &key, &data) < 0)
		return NULL;

	return data;
}

static int iface_ipip_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *conf,
	const void *api_info
) {
	struct iface_info_ipip *cur = iface_info_ipip(iface);
	const struct gr_iface_info_ipip *next = api_info;
	struct ipip_key cur_key = {cur->local, cur->remote, iface->vrf_id};
	struct ipip_key next_key = {next->local, next->remote, conf->vrf_id};
	int ret;

	if (set_attrs & (GR_IFACE_SET_VRF | GR_IPIP_SET_LOCAL | GR_IPIP_SET_REMOTE)) {
		if (conf->vrf_id >= GR_MAX_VRFS)
			return errno_set(EOVERFLOW);

		if (rte_hash_lookup(ipip_hash, &next_key) >= 0)
			return errno_set(EADDRINUSE);

		if (fib4_lookup(conf->vrf_id, next->local) == NULL)
			return -errno;
		if (fib4_lookup(conf->vrf_id, next->remote) == NULL)
			return -errno;

		if (memcmp(&cur_key, &next_key, sizeof(cur_key)) != 0)
			rte_hash_del_key(ipip_hash, &cur_key);

		if ((ret = rte_hash_add_key_data(ipip_hash, &next_key, iface)) < 0)
			return errno_log(-ret, "rte_hash_add_key_data");

		cur->local = next->local;
		cur->remote = next->remote;
	}

	return 0;
}

static int iface_ipip_fini(struct iface *iface) {
	struct iface_info_ipip *ipip = iface_info_ipip(iface);
	struct ipip_key key = {ipip->local, ipip->remote, iface->vrf_id};

	rte_hash_del_key(ipip_hash, &key);

	return 0;
}

static int iface_ipip_init(struct iface *iface, const void *api_info) {
	struct gr_iface conf;
	int ret;

	if (iface->mtu == 0)
		iface->mtu = 1480;

	conf.base = iface->base;

	ret = iface_ipip_reconfig(iface, IFACE_SET_ALL, &conf, api_info);
	if (ret < 0) {
		iface_ipip_fini(iface);
		errno = -ret;
	}

	return ret;
}

static void ipip_to_api(void *info, const struct iface *iface) {
	const struct iface_info_ipip *ipip = iface_info_ipip(iface);
	struct gr_iface_info_ipip *api = info;

	*api = ipip->base;
}

static struct iface_type iface_type_ipip = {
	.id = GR_IFACE_TYPE_IPIP,
	.name = "ipip",
	.pub_size = sizeof(struct gr_iface_info_ipip),
	.priv_size = sizeof(struct iface_info_ipip),
	.init = iface_ipip_init,
	.reconfig = iface_ipip_reconfig,
	.fini = iface_ipip_fini,
	.to_api = ipip_to_api,
};

static void ipip_init(struct event_base *) {
	struct rte_hash_parameters params = {
		.name = "ipip",
		.entries = MAX_IFACES,
		.key_len = sizeof(struct ipip_key),
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	ipip_hash = rte_hash_create(&params);
	if (ipip_hash == NULL)
		ABORT("rte_hash_create(ipip)");

	struct rte_hash_rcu_config rcu_config = {
		.v = gr_datapath_rcu(), .mode = RTE_HASH_QSBR_MODE_SYNC
	};
	rte_hash_rcu_qsbr_add(ipip_hash, &rcu_config);
}

static void ipip_fini(struct event_base *) {
	rte_hash_free(ipip_hash);
	ipip_hash = NULL;
}

static struct gr_module ipip_module = {
	.name = "ipip",
	.depends_on = "rcu",
	.init = ipip_init,
	.fini = ipip_fini,
};

RTE_INIT(ipip_constructor) {
	gr_register_module(&ipip_module);
	iface_type_register(&iface_type_ipip);
}
