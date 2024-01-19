// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#include "br_net_types.h"

#include <br_api.h>
#include <br_control.h>
#include <br_ip_msg.h>
#include <br_ip_types.h>
#include <br_log.h>
#include <br_nh4.h>
#include <br_queue.h>

#include <rte_bitmap.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_mempool.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_mempool *nh_pool;

static struct api_out nh4_add(const void *request, void **response) {
	const struct br_ip_nh4_add_req *req = request;
	struct br_ip_nh4 *nh;
	int ret;

	(void)response;

	if (req->nh.host == 0)
		return api_out(EINVAL, 0);
	if (!rte_eth_dev_is_valid_port(req->nh.port_id))
		return api_out(ENODEV, 0);

	if (rte_hash_lookup_data(ip4_next_hops, &req->nh.host, (void **)&nh) >= 0) {
		if (!req->exist_ok)
			return api_out(EEXIST, 0);
		nh->port_id = req->nh.port_id;
		memcpy(&nh->mac, &req->nh.mac, sizeof(nh->mac));
		return api_out(0, 0);
	}

	if (rte_mempool_get(nh_pool, (void **)&nh) < 0)
		return api_out(ENOMEM, 0);

	memcpy(nh, &req->nh, sizeof(*nh));

	if ((ret = rte_hash_add_key_data(ip4_next_hops, &nh->host, nh)) < 0) {
		rte_mempool_put(nh_pool, nh);
		return api_out(-ret, 0);
	}

	return api_out(0, 0);
}

static struct api_out nh4_del(const void *request, void **response) {
	const struct br_ip_nh4_del_req *req = request;
	struct nh4 *nh;
	int32_t pos;

	(void)response;

	pos = rte_hash_lookup_data(ip4_next_hops, &req->host, (void **)&nh);
	if (pos == -ENOENT && req->missing_ok)
		return api_out(0, 0);
	if (pos < 0)
		return api_out(-pos, 0);

	rte_mempool_put(nh_pool, nh);

	pos = rte_hash_del_key(ip4_next_hops, &req->host);
	// TODO: use RCU to avoid freeing while datapath is still using
	rte_hash_free_key_with_position(ip4_next_hops, pos);

	return api_out(0, 0);
}

static struct api_out nh4_list(const void *request, void **response) {
	struct br_ip_nh4_list_resp *resp = NULL;
	struct br_ip_nh4 *nh;
	uint32_t iter, num;
	ip4_addr_t *host;
	size_t len;

	(void)request;

	num = rte_hash_count(ip4_next_hops);
	len = sizeof(*resp) + num * sizeof(struct br_ip_nh4);
	if ((resp = malloc(len)) == NULL)
		return api_out(ENOMEM, 0);

	num = 0;
	iter = 0;
	while (rte_hash_iterate(ip4_next_hops, (const void **)&host, (void **)&nh, &iter) >= 0) {
		resp->nhs[num].host = nh->host;
		resp->nhs[num].port_id = nh->port_id;
		memcpy(&resp->nhs[num].mac, &nh->mac, sizeof(resp->nhs[num].mac));
		num++;
	}

	resp->n_nhs = num;
	*response = resp;

	return api_out(0, len);
}

// XXX: why not 1337, eh?
#define MAX_NEXT_HOPS 1024

struct rte_hash *ip4_next_hops;

static void nh4_init(void) {
	nh_pool = rte_mempool_create(
		"nh4",
		MAX_NEXT_HOPS,
		sizeof(ip4_addr_t),
		0, // cache_size
		0, // private_data_size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		0,
		RTE_MEMPOOL_F_NO_CACHE_ALIGN | RTE_MEMPOOL_F_SP_PUT | RTE_MEMPOOL_F_NO_IOVA_CONTIG
	);
	if (nh_pool == NULL) {
		LOG(EMERG, "rte_mempool_create: %s", rte_strerror(rte_errno));
		abort();
	}

	struct rte_hash_parameters params = {
		.name = "nh4",
		.entries = 1024, // XXX: why not 1337, eh?
		.key_len = sizeof(ip4_addr_t),
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	ip4_next_hops = rte_hash_create(&params);
	if (ip4_next_hops == NULL) {
		LOG(EMERG, "rte_hash_create: %s", rte_strerror(rte_errno));
		abort();
	}
	// TODO: add RCU config?
	// struct rte_hash_rcu_config rcu;
	// rte_hash_rcu_qsbr_add(ip4_next_hops, &rcu);
}

static void nh4_fini(void) {
	rte_hash_free(ip4_next_hops);
}

static struct br_api_handler nh4_add_handler = {
	.name = "nh4 add",
	.request_type = BR_IP_NH4_ADD,
	.callback = nh4_add,
};
static struct br_api_handler nh4_del_handler = {
	.name = "nh4 del",
	.request_type = BR_IP_NH4_DEL,
	.callback = nh4_del,
};
static struct br_api_handler nh4_list_handler = {
	.name = "nh4 list",
	.request_type = BR_IP_NH4_LIST,
	.callback = nh4_list,
};

static struct br_module nh4_module = {
	.init = nh4_init,
	.fini = nh4_fini,
};

RTE_INIT(control_ip_init) {
	br_register_api_handler(&nh4_add_handler);
	br_register_api_handler(&nh4_del_handler);
	br_register_api_handler(&nh4_list_handler);
	br_register_module(&nh4_module);
}
