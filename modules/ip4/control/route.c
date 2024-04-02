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

#include <rte_bitmap.h>
#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_fib.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_rcu_qsbr.h>
#include <rte_rib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_fib *fib;
static struct rte_rib *rib;

struct rte_fib *ip4_fib_get(void) {
	return fib;
}

static struct api_out route4_add(const void *request, void **response) {
	const struct br_ip4_route_add_req *req = request;
	struct rte_rib_node *rn;
	int ret;

	(void)response;

	if ((rn = rte_rib_lookup_exact(rib, ntohl(req->dest.ip), req->dest.prefixlen)) != NULL) {
		uint64_t old_gw;
		rte_rib_get_nh(rn, &old_gw);
		if (req->nh == old_gw && req->exist_ok)
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	ret = rte_fib_add(fib, ntohl(req->dest.ip), req->dest.prefixlen, req->nh);
	return api_out(-ret, 0);
}

static struct api_out route4_del(const void *request, void **response) {
	const struct br_ip4_route_del_req *req = request;

	(void)response;

	if (rte_rib_lookup_exact(rib, ntohl(req->dest.ip), req->dest.prefixlen) == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}

	rte_fib_delete(fib, ntohl(req->dest.ip), req->dest.prefixlen);
	return api_out(0, 0);
}

static struct api_out route4_get(const void *request, void **response) {
	const struct br_ip4_route_get_req *req = request;
	struct br_ip4_route_get_resp *resp = NULL;
	struct next_hop *next_hop = NULL;
	struct rte_rib_node *rn;
	uint64_t ip;

	if ((rn = rte_rib_lookup(rib, req->dest)) == NULL)
		return api_out(ENETUNREACH, 0);
	rte_rib_get_nh(rn, &ip);

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);

	resp->nh.host = ip;

	if (next_hop_lookup(ip4_next_hops_hash_get(), ip, &next_hop) == 0) {
		resp->nh.port_id = next_hop->port_id;
		memcpy(&resp->nh.mac, &next_hop->eth_addr[0], sizeof(resp->nh.mac));
		resp->nh.flags = next_hop->flags;
	} else {
		resp->nh.port_id = UINT16_MAX;
		br_eth_addr_broadcast(&resp->nh.mac);
		resp->nh.flags = BR_IP4_NH_F_UNKNOWN;
	}

	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out route4_list(const void *request, void **response) {
	struct br_ip4_route_list_resp *resp = NULL;
	struct rte_rib *rib = rte_fib_get_rib(fib);
	struct rte_rib_node *rn = NULL;
	struct br_ip4_route *r;
	size_t num, len;
	uint64_t gw;
	uint32_t ip;

	(void)request;

	num = 0;
	while ((rn = rte_rib_get_nxt(rib, 0, 0, rn, RTE_RIB_GET_NXT_ALL)) != NULL)
		num++;
	// FIXME: remove this when rte_rib_get_nxt returns a default route, if any is configured
	if (rte_rib_lookup_exact(rib, 0, 0) != NULL)
		num++;

	len = sizeof(*resp) + num * sizeof(struct br_ip4_route);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	while ((rn = rte_rib_get_nxt(rib, 0, 0, rn, RTE_RIB_GET_NXT_ALL)) != NULL) {
		r = &resp->routes[resp->n_routes++];
		rte_rib_get_ip(rn, &ip);
		rte_rib_get_nh(rn, &gw);
		rte_rib_get_depth(rn, &r->dest.prefixlen);
		r->dest.ip = htonl(ip);
		r->nh = gw;
	}
	// FIXME: remove this when rte_rib_get_nxt returns a default route, if any is configured
	if ((rn = rte_rib_lookup_exact(rib, 0, 0)) != NULL) {
		r = &resp->routes[resp->n_routes++];
		rte_rib_get_nh(rn, &gw);
		r->dest.ip = 0;
		r->dest.prefixlen = 0;
		r->nh = gw;
	}
	*response = resp;

	return api_out(0, len);
}

// XXX: why not 1337, eh?
#define BR_IP4_MAX_ROUTES (1 << 16)

static void route4_init(void) {
	struct rte_fib_conf conf = {
		.type = RTE_FIB_DIR24_8,
		.default_nh = BR_IP4_ROUTE_UNKNOWN ,
		.max_routes = BR_IP4_MAX_ROUTES,
		.rib_ext_sz = 0,
		.dir24_8 = {
			// DIR24_8 uses 1 bit to store routing table structure
			// information.  4 bytes next hops are not enough to
			// store IPv4 addresses.  Use 8 bytes next hops.
			.nh_sz = RTE_FIB_DIR24_8_8B,
			.num_tbl8 = 1 << 15,
		},
	};
	fib = rte_fib_create("ip4-route", SOCKET_ID_ANY, &conf);
	if (fib == NULL)
		ABORT("rte_fib_create: %s", rte_strerror(rte_errno));
	rib = rte_fib_get_rib(fib);
}

static void route4_fini(void) {
	rib = NULL;
	rte_fib_free(fib);
	fib = NULL;
}

static struct br_api_handler route4_add_handler = {
	.name = "ipv4 route add",
	.request_type = BR_IP4_ROUTE_ADD,
	.callback = route4_add,
};
static struct br_api_handler route4_del_handler = {
	.name = "ipv4 route del",
	.request_type = BR_IP4_ROUTE_DEL,
	.callback = route4_del,
};
static struct br_api_handler route4_get_handler = {
	.name = "ipv4 route get",
	.request_type = BR_IP4_ROUTE_GET,
	.callback = route4_get,
};
static struct br_api_handler route4_list_handler = {
	.name = "ipv4 route list",
	.request_type = BR_IP4_ROUTE_LIST,
	.callback = route4_list,
};

static struct br_module route4_module = {
	.name = "ipv4 route",
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
