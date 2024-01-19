// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

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
#include <rte_mempool.h>
#include <rte_rib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_rib *ip4_rib;

static struct api_out route4_add(const void *request, void **response) {
	const struct br_ip_route4_add_req *req = request;
	struct rte_rib_node *route;
	struct br_ip_nh4 *nh;

	(void)response;

	if (rte_hash_lookup_data(ip4_next_hops, &req->nh, (void **)&nh) < 0)
		return api_out(ENETUNREACH, 0);

	route = rte_rib_lookup_exact(ip4_rib, req->dest.addr, req->dest.prefixlen);
	if (route != NULL) {
		if (!req->exist_ok)
			return api_out(EEXIST, 0);
		rte_rib_set_nh(route, req->nh);
		return api_out(0, 0);
	}

	route = rte_rib_insert(ip4_rib, req->dest.addr, req->dest.prefixlen);
	rte_rib_set_nh(route, req->nh);
	return api_out(0, 0);
}

static struct api_out route4_del(const void *request, void **response) {
	const struct br_ip_route4_del_req *req = request;

	(void)response;

	if (rte_rib_lookup_exact(ip4_rib, req->dest.addr, req->dest.prefixlen) == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}
	rte_rib_remove(ip4_rib, req->dest.addr, req->dest.prefixlen);

	return api_out(0, 0);
}

static struct api_out route4_list(const void *request, void **response) {
	struct br_ip_route4_list_resp *resp = NULL;
	struct rte_rib_node *route;
	size_t num, len;
	uint64_t nh;

	(void)request;

	num = 0;
	route = NULL;
	while ((route = rte_rib_get_nxt(ip4_rib, 0, 0, route, RTE_RIB_GET_NXT_ALL)) != NULL)
		num++;

	len = sizeof(*resp) + num * sizeof(struct br_ip_route4);
	if ((resp = malloc(len)) == NULL)
		return api_out(ENOMEM, 0);

	memset(resp, 0, len);

	num = 0;
	route = NULL;
	while ((route = rte_rib_get_nxt(ip4_rib, 0, 0, route, RTE_RIB_GET_NXT_ALL)) != NULL) {
		rte_rib_get_ip(route, &resp->routes[num].dest.addr);
		rte_rib_get_depth(route, &resp->routes[num].dest.prefixlen);
		rte_rib_get_nh(route, &nh);
		resp->routes[num].nh = (ip4_addr_t)nh;
		num++;
	}

	resp->n_routes = num;
	*response = resp;

	return api_out(0, len);
}

struct rte_fib *ip4_fib;

static void route4_init(void) {
	struct rte_fib_conf conf
		= {.type = RTE_FIB_DIR24_8,
		   .default_nh = NO_ROUTE,
		   .max_routes = MAX_ROUTES,
		   .rib_ext_sz = 0,
		   .dir24_8 = {
			   .nh_sz = RTE_FIB_DIR24_8_4B, // XXX: what the f is this?
			   .num_tbl8 = 1 << 15, // XXX: what the *actual* f is this?
		   }};
	ip4_fib = rte_fib_create("route4", 0, &conf);
	if (ip4_fib == NULL) {
		LOG(EMERG, "rte_fib_create: %s", rte_strerror(rte_errno));
		abort();
	}
	ip4_rib = rte_fib_get_rib(ip4_fib);
}

static void route4_fini(void) {
	rte_fib_free(ip4_fib);
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
static struct br_api_handler route4_list_handler = {
	.name = "route4 list",
	.request_type = BR_IP_ROUTE4_LIST,
	.callback = route4_list,
};

static struct br_module route4_module = {
	.init = route4_init,
	.fini = route4_fini,
};

RTE_INIT(control_ip_init) {
	br_register_api_handler(&route4_add_handler);
	br_register_api_handler(&route4_del_handler);
	br_register_api_handler(&route4_list_handler);
	br_register_module(&route4_module);
}
