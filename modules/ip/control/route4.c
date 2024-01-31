// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#include "ip_priv.h"

#include <br_api.h>
#include <br_control.h>
#include <br_ip_msg.h>
#include <br_ip_types.h>
#include <br_log.h>
#include <br_net_types.h>
#include <br_nh4.h>
#include <br_queue.h>
#include <br_route4.h>

#include <rte_bitmap.h>
#include <rte_ethdev.h>
#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_memory.h>
#include <rte_rib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_hash *routes;
static struct rte_fib *fib;

int route_lookup(ip4_addr_t dest, struct next_hop **nh) {
	uint64_t gateway = 0;
	int ret;

	dest = ntohl(dest);

	if (nh == NULL)
		return -EINVAL;
	if (fib == NULL)
		return -EIO;
	if ((ret = rte_fib_lookup_bulk(fib, &dest, &gateway, 1)) < 0)
		return -ret;
	if (gateway == NO_ROUTE)
		return -ENETUNREACH;
	if ((ret = next_hop_lookup(htonl((ip4_addr_t)gateway), nh)) < 0)
		return ret;

	return 0;
}

int route_lookup_exact(ip4_addr_t net, uint8_t prefix, struct next_hop **nh) {
	struct ip4_net network = {.addr = net, .prefixlen = prefix};
	uintptr_t gateway;
	int ret;

	if (nh == NULL)
		return -EINVAL;
	if (routes == NULL)
		return -EIO;
	if ((ret = rte_hash_lookup_data(routes, &network, (void **)&gateway)) < 0)
		return ret;
	if ((ret = next_hop_lookup(gateway, nh)) < 0)
		return ret;

	return 0;
}

int route_insert(ip4_addr_t net, uint8_t prefix, ip4_addr_t gw, bool force) {
	struct ip4_net network = {.addr = net, .prefixlen = prefix};
	struct next_hop *old_nh = NULL, *nh = NULL;
	int ret;

	if ((ret = next_hop_lookup(gw, &nh)) < 0)
		return ret;

	if (route_lookup_exact(net, prefix, &old_nh) == 0) {
		if (!force)
			return -EEXIST;
		if (gw == old_nh->ip)
			return 0;
	}
	if ((ret = rte_fib_add(fib, ntohl(net), prefix, (uint64_t)ntohl(gw))) < 0)
		return ret;

	if ((ret = rte_hash_add_key_data(routes, &network, (void *)(uintptr_t)gw)) < 0)
		return ret;

	if (old_nh != NULL)
		old_nh->ref_count--;
	nh->ref_count++;

	return 0;
}

int route_delete(ip4_addr_t net, uint8_t prefix, bool force) {
	struct ip4_net network = {.addr = net, .prefixlen = prefix};
	struct next_hop *nh;
	int ret;

	if ((ret = route_lookup_exact(net, prefix, &nh)) < 0) {
		if (ret == -ENOENT && force)
			return 0;
		return ret;
	}

	rte_fib_delete(fib, ntohl(net), prefix);

	ret = rte_hash_del_key(routes, &network);
	// TODO: use RCU to avoid freeing while datapath is still using
	rte_hash_free_key_with_position(routes, ret);

	return 0;
}

static struct api_out route4_add(const void *request, void **response) {
	const struct br_ip_route4_add_req *req = request;
	int ret;

	(void)response;

	ret = route_insert(req->dest.addr, req->dest.prefixlen, req->nh, req->exist_ok);
	return api_out(-ret, 0);
}

static struct api_out route4_del(const void *request, void **response) {
	const struct br_ip_route4_del_req *req = request;
	int ret;

	(void)response;

	ret = route_delete(req->dest.addr, req->dest.prefixlen, req->missing_ok);
	return api_out(-ret, 0);
}

static struct api_out route4_get(const void *request, void **response) {
	const struct br_ip_route4_get_req *req = request;
	struct br_ip_route4_get_resp *resp = NULL;
	struct next_hop *next_hop = NULL;
	int ret;

	if ((ret = route_lookup(req->dest, &next_hop)) < 0)
		return api_out(-ret, 0);

	if ((resp = malloc(sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);

	resp->nh.host = next_hop->ip;
	resp->nh.port_id = next_hop->port_id;
	memcpy(&resp->nh.mac, &next_hop->eth_addr[0], sizeof(resp->nh.mac));
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out route4_list(const void *request, void **response) {
	struct br_ip_route4_list_resp *resp = NULL;
	struct ip4_net *net;
	size_t num, len;
	uintptr_t gw;
	uint32_t iter;

	(void)request;

	num = rte_hash_count(routes);
	len = sizeof(*resp) + num * sizeof(struct br_ip_route4);
	if ((resp = malloc(len)) == NULL)
		return api_out(ENOMEM, 0);

	num = 0;
	iter = 0;
	while (rte_hash_iterate(routes, (const void **)&net, (void **)&gw, &iter) >= 0) {
		memcpy(&resp->routes[num].dest, net, sizeof(resp->routes[num].dest));
		resp->routes[num].nh = gw;
		num++;
	}

	resp->n_routes = num;
	*response = resp;

	return api_out(0, len);
}

static void route4_init(void) {
	struct rte_fib_conf conf = {
		.type = RTE_FIB_DIR24_8,
		.default_nh = NO_ROUTE,
		.max_routes = MAX_ROUTES,
		.rib_ext_sz = 0,
		.dir24_8 = {
			   .nh_sz = RTE_FIB_DIR24_8_4B,
			   .num_tbl8 = 1 << 15,
		},
	};
	fib = rte_fib_create(IP4_FIB_NAME, SOCKET_ID_ANY, &conf);
	if (fib == NULL)
		ABORT("rte_fib_create: %s", rte_strerror(rte_errno));

	struct rte_hash_parameters params = {
		.name = "route4",
		.entries = MAX_ROUTES,
		.key_len = sizeof(struct ip4_net),
	};
	routes = rte_hash_create(&params);
	if (routes == NULL)
		ABORT("rte_hash_create: %s", rte_strerror(rte_errno));
}

static void route4_fini(void) {
	rte_fib_free(fib);
	fib = NULL;
	rte_hash_free(routes);
	routes = NULL;
}

static struct br_api_handler route4_add_handler = {
	.name = "route4 add",
	.request_type = BR_IP_ROUTE4_ADD,
	.callback = route4_add,
};
static struct br_api_handler route4_del_handler = {
	.name = "route4 del",
	.request_type = BR_IP_ROUTE4_DEL,
	.callback = route4_del,
};
static struct br_api_handler route4_get_handler = {
	.name = "route4 get",
	.request_type = BR_IP_ROUTE4_GET,
	.callback = route4_get,
};
static struct br_api_handler route4_list_handler = {
	.name = "route4 list",
	.request_type = BR_IP_ROUTE4_LIST,
	.callback = route4_list,
};

static struct br_module route4_module = {
	.name = "route4",
	.init = route4_init,
	.fini = route4_fini,
	.fini_prio = 10000,
};

RTE_INIT(control_ip_init) {
	br_register_api_handler(&route4_add_handler);
	br_register_api_handler(&route4_del_handler);
	br_register_api_handler(&route4_get_handler);
	br_register_api_handler(&route4_list_handler);
	br_register_module(&route4_module);
}
