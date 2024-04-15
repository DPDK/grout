// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_api.h>
#include <br_control.h>
#include <br_ip4.h>
#include <br_ip4_control.h>
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

static struct next_hop *addrs[RTE_MAX_ETHPORTS];

struct next_hop *ip4_addr_get(uint16_t port_id) {
	// no check for index, for data path use
	return addrs[port_id];
}

static struct api_out addr_add(const void *request, void **response) {
	const struct br_ip4_addr_add_req *req = request;
	struct next_hop *nh;
	uint32_t nh_idx;
	int ret;

	(void)response;

	if ((nh = ip4_addr_get(req->addr.port_id)) != NULL) {
		if (req->exist_ok && req->addr.addr.ip == nh->ip
		    && req->addr.addr.prefixlen == nh->prefixlen)
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}
	if (ip4_next_hop_lookup(req->addr.addr.ip, &nh_idx, &nh) == 0)
		return api_out(EADDRINUSE, 0);
	if (!rte_eth_dev_is_valid_port(req->addr.port_id))
		return api_out(ENODEV, 0);

	if ((ret = ip4_next_hop_lookup_add(req->addr.addr.ip, &nh_idx, &nh)) < 0)
		return api_out(-ret, 0);

	nh->port_id = req->addr.port_id;
	nh->prefixlen = req->addr.addr.prefixlen;
	nh->flags = BR_IP4_NH_F_LOCAL | BR_IP4_NH_F_LINK | BR_IP4_NH_F_REACHABLE
		| BR_IP4_NH_F_STATIC;
	if ((ret = rte_eth_macaddr_get(nh->port_id, &nh->lladdr)) < 0)
		return api_out(-ret, 0);

	ret = ip4_route_insert(nh->ip, nh->prefixlen, nh_idx, nh);
	if (ret == 0)
		addrs[nh->port_id] = nh;
	else
		ip4_next_hop_decref(nh);

	return api_out(-ret, 0);
}

static struct api_out addr_del(const void *request, void **response) {
	const struct br_ip4_addr_del_req *req = request;
	struct next_hop *nh;

	(void)response;

	if ((nh = ip4_addr_get(req->addr.port_id)) == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}
	if (nh->ip != req->addr.addr.ip || nh->prefixlen != req->addr.addr.prefixlen)
		return api_out(ENOENT, 0);

	if ((nh->flags & (BR_IP4_NH_F_LOCAL | BR_IP4_NH_F_LINK)) || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	ip4_route_delete(nh->ip, nh->prefixlen);
	addrs[req->addr.port_id] = NULL;

	return api_out(0, 0);
}

static struct api_out addr_list(const void *request, void **response) {
	struct br_ip4_addr_list_resp *resp = NULL;
	const struct next_hop *nh;
	struct br_ip4_addr *addr;
	uint16_t port_id, num;
	size_t len;

	(void)request;

	num = 0;
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (ip4_addr_get(port_id) != NULL)
			num++;
	}

	len = sizeof(*resp) + num * sizeof(struct br_ip4_addr);
	if ((resp = calloc(len, 1)) == NULL)
		return api_out(ENOMEM, 0);

	num = 0;
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		nh = ip4_addr_get(port_id);
		if (nh == NULL)
			continue;
		addr = &resp->addrs[resp->n_addrs++];
		addr->addr.ip = nh->ip;
		addr->addr.prefixlen = nh->prefixlen;
		addr->port_id = nh->port_id;
	}

	*response = resp;

	return api_out(0, len);
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

RTE_INIT(ip4_addr_init) {
	br_register_api_handler(&addr_add_handler);
	br_register_api_handler(&addr_del_handler);
	br_register_api_handler(&addr_list_handler);
}
