// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip4_priv.h"

#include <br_api.h>
#include <br_control.h>
#include <br_ip4_control.h>
#include <br_ip4_msg.h>
#include <br_ip4_types.h>
#include <br_log.h>
#include <br_net_types.h>
#include <br_queue.h>

#include <rte_bitmap.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_rcu_qsbr.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_mempool *nh_pool;
static struct rte_hash *nh_hash;
static struct rte_rcu_qsbr *rcu;

struct rte_hash *ip4_next_hops_hash_get(void) {
	return nh_hash;
}

struct rte_rcu_qsbr *ip4_next_hops_rcu_get(void) {
	return rcu;
}

int next_hop_lookup(ip4_addr_t gw, struct next_hop **nh) {
	void *data = NULL;
	int ret;
	if (nh_hash == NULL)
		return -EIO;
	if ((ret = rte_hash_lookup_data(nh_hash, &gw, &data)) < 0) {
		return ret;
	}
	*nh = data;
	return 0;
}

int next_hop_delete(ip4_addr_t gw, bool force) {
	const struct next_hop *nh;
	void *data = NULL;
	int32_t pos;

	if (nh_hash == NULL)
		return -EIO;

	pos = rte_hash_lookup_data(nh_hash, &gw, &data);
	if (pos == -ENOENT && force)
		return 0;
	if (pos < 0)
		return -pos;
	nh = data;
	if (nh->ref_count > 1)
		return -EBUSY;

	if ((pos = route_delete(gw, 32, force)) < 0)
		return pos;
	rte_hash_del_key(nh_hash, &gw);

	return 0;
}

static struct api_out nh4_add(const void *request, void **response) {
	const struct br_ip4_nh_add_req *req = request;
	struct next_hop *nh, *old_nh = NULL;
	struct rte_ether_addr src;
	void *data = NULL;
	int ret;

	(void)response;

	if (req->nh.host == 0)
		return api_out(EINVAL, 0);
	if (rte_eth_macaddr_get(req->nh.port_id, &src) < 0)
		return api_out(ENODEV, 0);
	if (next_hop_lookup(req->nh.host, &old_nh) == 0 && !req->exist_ok)
		return api_out(EEXIST, 0);
	if (rte_mempool_get(nh_pool, &data) < 0)
		return api_out(ENOMEM, 0);

	nh = data;
	memset(nh, 0, sizeof(*nh));
	nh->ip = req->nh.host;
	nh->port_id = req->nh.port_id;
	memcpy(&nh->eth_addr[0], &req->nh.mac, sizeof(nh->eth_addr[0]));
	// FIXME: update all next hops when changing a port's mac address
	memcpy(&nh->eth_addr[1], &src, sizeof(nh->eth_addr[1]));

	if ((ret = rte_hash_add_key_data(nh_hash, &req->nh.host, nh)) < 0) {
		rte_mempool_put(nh_pool, nh);
		return api_out(-ret, 0);
	}
	if ((ret = route_insert(req->nh.host, 32, req->nh.host, req->exist_ok)) < 0)
		return api_out(-ret, 0);

	if (old_nh != NULL) {
		// XXX: rte_hash_add_key_data does not free the data when the key already exists in
		// the hash map. We need to free the data manually.
		rte_rcu_qsbr_synchronize(rcu, RTE_QSBR_THRID_INVALID);
		rte_mempool_put(nh_pool, nh);
	}

	return api_out(0, 0);
}

static struct api_out nh4_del(const void *request, void **response) {
	const struct br_ip4_nh_del_req *req = request;
	int ret;

	(void)response;

	if ((ret = next_hop_delete(req->host, req->missing_ok)) < 0)
		return api_out(-ret, 0);

	return api_out(0, 0);
}

static struct api_out nh4_list(const void *request, void **response) {
	struct br_ip4_nh_list_resp *resp = NULL;
	uint32_t iter, num;
	const void *key;
	void *data;
	size_t len;

	(void)request;

	num = rte_hash_count(nh_hash);
	len = sizeof(*resp) + num * sizeof(struct br_ip4_nh);
	if ((resp = malloc(len)) == NULL)
		return api_out(ENOMEM, 0);

	num = 0;
	iter = 0;
	while (rte_hash_iterate(nh_hash, &key, &data, &iter) >= 0) {
		struct next_hop *nh = data;
		resp->nhs[num].host = nh->ip;
		resp->nhs[num].port_id = nh->port_id;
		memcpy(&resp->nhs[num].mac, &nh->eth_addr[0], sizeof(resp->nhs[num].mac));
		num++;
	}

	resp->n_nhs = num;
	*response = resp;

	return api_out(0, len);
}

static void next_hop_free(void *priv, void *next_hop) {
	(void)priv;
	rte_mempool_put(nh_pool, next_hop);
}

// XXX: why not 1337, eh?
#define MAX_NEXT_HOPS 1024

static void nh4_init(void) {
	nh_pool = rte_mempool_create(
		"nh4",
		MAX_NEXT_HOPS,
		sizeof(struct next_hop),
		0, // cache_size
		0, // private_data_size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		SOCKET_ID_ANY,
		RTE_MEMPOOL_F_SP_PUT | RTE_MEMPOOL_F_NO_IOVA_CONTIG
	);
	if (nh_pool == NULL)
		ABORT("rte_mempool_create: %s", rte_strerror(rte_errno));

	struct rte_hash_parameters params = {
		.name = "ip4-nexthops",
		.entries = 1024, // XXX: why not 1337, eh?
		.key_len = sizeof(ip4_addr_t),
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	nh_hash = rte_hash_create(&params);
	if (nh_hash == NULL)
		ABORT("rte_hash_create: %s", rte_strerror(rte_errno));

	size_t sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	rcu = rte_malloc("nh4-rcu", sz, RTE_CACHE_LINE_SIZE);
	if (rcu == NULL)
		ABORT("rte_malloc(rcu): %s", rte_strerror(rte_errno));

	if (rte_rcu_qsbr_init(rcu, RTE_MAX_LCORE))
		ABORT("rte_rcu_qsbr_init: %s", rte_strerror(rte_errno));

	struct rte_hash_rcu_config rcu_conf = {
		.v = rcu,
		.free_key_data_func = next_hop_free,
	};
	if (rte_hash_rcu_qsbr_add(nh_hash, &rcu_conf))
		ABORT("rte_hash_rcu_qsbr_add: %s", rte_strerror(rte_errno));
}

static void nh4_fini(void) {
	rte_hash_free(nh_hash);
	nh_hash = NULL;
	rte_mempool_free(nh_pool);
	nh_pool = NULL;
	rte_free(rcu);
	rcu = NULL;
}

static void nh4_init_dp(void) {
	rte_rcu_qsbr_thread_register(rcu, rte_lcore_id());
}

static void nh4_fini_dp(void) {
	rte_rcu_qsbr_thread_unregister(rcu, rte_lcore_id());
}

static struct br_api_handler nh4_add_handler = {
	.name = "ipv4 nexthop add",
	.request_type = BR_IP4_NH_ADD,
	.callback = nh4_add,
};
static struct br_api_handler nh4_del_handler = {
	.name = "ipv4 nexthop del",
	.request_type = BR_IP4_NH_DEL,
	.callback = nh4_del,
};
static struct br_api_handler nh4_list_handler = {
	.name = "ipv4 nexthop list",
	.request_type = BR_IP4_NH_LIST,
	.callback = nh4_list,
};

static struct br_module nh4_module = {
	.name = "ipv4 nexthop",
	.init = nh4_init,
	.fini = nh4_fini,
	.init_dp = nh4_init_dp,
	.fini_dp = nh4_fini_dp,
};

RTE_INIT(control_ip_init) {
	br_register_api_handler(&nh4_add_handler);
	br_register_api_handler(&nh4_del_handler);
	br_register_api_handler(&nh4_list_handler);
	br_register_module(&nh4_module);
}
