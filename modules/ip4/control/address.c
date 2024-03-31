// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_api.h>
#include <br_control.h>
#include <br_ip4_control.h>
#include <br_ip4_msg.h>
#include <br_ip4_types.h>
#include <br_log.h>
#include <br_net_types.h>
#include <br_queue.h>

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_rcu_qsbr.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_mempool *addr_pool;
static struct rte_hash *addr_hash;
static struct rte_rcu_qsbr *rcu;

struct rte_hash *ip4_address_hash_get(void) {
	return addr_hash;
}

struct rte_rcu_qsbr *ip4_address_rcu_get(void) {
	return rcu;
}

static struct api_out addr_add(const void *request, void **response) {
	const struct br_ip4_addr_add_req *req = request;
	struct br_ip4_addr *addr;
	void *data = NULL;
	int ret;

	(void)response;

	if (rte_hash_lookup_data(addr_hash, &req->addr.ip.addr, &data) == 0) {
		addr = data;
		if (req->addr.ip.prefixlen != addr->ip.prefixlen)
			return api_out(EADDRINUSE, 0);
		if (req->addr.port_id != addr->port_id)
			return api_out(EADDRINUSE, 0);
		// address already set with the same prefix and same port
		if (req->exist_ok)
			return api_out(0, 0);
		return api_out(EADDRINUSE, 0);
	}

	if (!rte_eth_dev_is_valid_port(req->addr.port_id))
		return api_out(ENODEV, 0);

	if (rte_mempool_get(addr_pool, &data) < 0)
		return api_out(ENOMEM, 0);

	addr = data;
	memcpy(addr, &req->addr, sizeof(*addr));

	if ((ret = rte_hash_add_key_data(addr_hash, &addr->ip.addr, addr)) < 0) {
		rte_mempool_put(addr_pool, addr);
		return api_out(-ret, 0);
	}

	return api_out(0, 0);
}

static struct api_out addr_del(const void *request, void **response) {
	const struct br_ip4_addr_del_req *req = request;
	struct br_ip4_addr *addr;
	void *data = NULL;
	int ret;

	(void)response;

	if ((ret = rte_hash_lookup_data(addr_hash, &req->addr.ip.addr, &data)) < 0) {
		if (ret == -ENOENT && req->missing_ok)
			return api_out(0, 0);
		return api_out(ENXIO, 0);
	}

	addr = data;
	if (addr->ip.prefixlen != req->addr.ip.prefixlen)
		return api_out(ENXIO, 0);
	if (addr->port_id != req->addr.port_id)
		return api_out(ENXIO, 0);

	rte_hash_del_key(addr_hash, &req->addr.ip.addr);
	return api_out(0, 0);
}

static struct api_out addr_list(const void *request, void **response) {
	struct br_ip4_addr_list_resp *resp = NULL;
	uint32_t iter, num;
	const void *key;
	void *data;
	size_t len;

	(void)request;

	num = rte_hash_count(addr_hash);
	len = sizeof(*resp) + num * sizeof(struct br_ip4_addr);
	if ((resp = malloc(len)) == NULL)
		return api_out(ENOMEM, 0);

	num = 0;
	iter = 0;
	while (rte_hash_iterate(addr_hash, &key, &data, &iter) >= 0) {
		const struct br_ip4_addr *addr = data;
		memcpy(&resp->addrs[num++], addr, sizeof(*addr));
	}

	resp->n_addrs = num;
	*response = resp;

	return api_out(0, len);
}

// used by rte_hash rcu mechanism
static void addr_free(void *priv, void *address) {
	(void)priv;
	rte_mempool_put(addr_pool, address);
}

static void addr_init(void) {
	addr_pool = rte_mempool_create(
		"ip4-address",
		RTE_MAX_ETHPORTS * 8,
		sizeof(struct br_ip4_addr),
		0, // cache_size
		0, // private_data_size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		SOCKET_ID_ANY,
		RTE_MEMPOOL_F_SP_PUT | RTE_MEMPOOL_F_NO_IOVA_CONTIG
	);
	if (addr_pool == NULL)
		ABORT("rte_mempool_create: %s", rte_strerror(rte_errno));

	struct rte_hash_parameters params = {
		.name = "ip4-address",
		.entries = RTE_MAX_ETHPORTS * 8,
		.key_len = sizeof(ip4_addr_t),
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	addr_hash = rte_hash_create(&params);
	if (addr_hash == NULL)
		ABORT("rte_hash_create: %s", rte_strerror(rte_errno));

	size_t sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	rcu = rte_malloc("ip4-addr-rcu", sz, RTE_CACHE_LINE_SIZE);
	if (rcu == NULL)
		ABORT("rte_malloc(rcu): %s", rte_strerror(rte_errno));

	if (rte_rcu_qsbr_init(rcu, RTE_MAX_LCORE))
		ABORT("rte_rcu_qsbr_init: %s", rte_strerror(rte_errno));

	struct rte_hash_rcu_config rcu_conf = {
		.v = rcu,
		.free_key_data_func = addr_free,
	};
	if (rte_hash_rcu_qsbr_add(addr_hash, &rcu_conf))
		ABORT("rte_hash_rcu_qsbr_add: %s", rte_strerror(rte_errno));
}

static void addr_fini(void) {
	rte_hash_free(addr_hash);
	addr_hash = NULL;
	rte_mempool_free(addr_pool);
	addr_pool = NULL;
	rte_free(rcu);
	rcu = NULL;
}

static struct br_api_handler addr_add_handler = {
	.name = "ipv4 address add",
	.request_type = BR_IP4_ADDR_ADD,
	.callback = addr_add,
};
static struct br_api_handler addr_del_handler = {
	.name = "ipv4 address del",
	.request_type = BR_IP4_ADDR_DEL,
	.callback = addr_del,
};
static struct br_api_handler addr_list_handler = {
	.name = "ipv4 address list",
	.request_type = BR_IP4_ADDR_LIST,
	.callback = addr_list,
};

static struct br_module addr_module = {
	.name = "ipv4 address",
	.init = addr_init,
	.fini = addr_fini,
	.fini_prio = 10000,
};

RTE_INIT(ip4_addr_init) {
	br_register_api_handler(&addr_add_handler);
	br_register_api_handler(&addr_del_handler);
	br_register_api_handler(&addr_list_handler);
	br_register_module(&addr_module);
}
