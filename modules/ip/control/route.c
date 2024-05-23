// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_api.h>
#include <br_control.h>
#include <br_ip4.h>
#include <br_ip4_control.h>
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

static struct rte_fib **vrf_fibs;
#define BLACKHOLE (MAX_NEXT_HOPS + 1)

static struct rte_fib_conf fib_conf = {
	.type = RTE_FIB_DIR24_8,
	.default_nh = BLACKHOLE,
	.max_routes = MAX_ROUTES,
	.rib_ext_sz = 0,
	.dir24_8 = {
		.nh_sz = RTE_FIB_DIR24_8_4B,
		.num_tbl8 = 1 << 15,
	},
};

static struct rte_fib *get_fib(uint16_t vrf_id) {
	struct rte_fib *fib;

	if (vrf_id >= MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL)
		return errno_set_null(ENONET);

	return fib;
}

static struct rte_fib *get_or_create_fib(uint16_t vrf_id) {
	struct rte_fib *fib;

	if (vrf_id >= MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL) {
		char name[64];

		snprintf(name, sizeof(name), "vrf_%u", vrf_id);
		fib = rte_fib_create(name, SOCKET_ID_ANY, &fib_conf);
		if (fib == NULL)
			return errno_set_null(rte_errno);

		vrf_fibs[vrf_id] = fib;
	}

	return fib;
}

struct nexthop *ip4_route_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	uint32_t host_order_ip = rte_be_to_cpu_32(ip);
	struct rte_fib *fib = get_fib(vrf_id);
	uint64_t nh_idx;

	if (fib == NULL)
		return NULL;

	rte_fib_lookup_bulk(fib, &host_order_ip, &nh_idx, 1);
	if (nh_idx == BLACKHOLE)
		return errno_set_null(EHOSTUNREACH);

	return ip4_nexthop_get(nh_idx);
}

struct nexthop *ip4_route_lookup_exact(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen) {
	uint32_t host_order_ip = rte_be_to_cpu_32(ip);
	struct rte_fib *fib = get_fib(vrf_id);
	struct rte_rib_node *rn;
	struct rte_rib *rib;
	uint64_t nh_idx;

	if (fib == NULL)
		return NULL;

	rib = rte_fib_get_rib(fib);
	rn = rte_rib_lookup_exact(rib, host_order_ip, prefixlen);
	if (rn == NULL)
		return errno_set_null(ENETUNREACH);

	rte_rib_get_nh(rn, &nh_idx);
	return ip4_nexthop_get(nh_idx);
}

int ip4_route_insert(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	uint32_t nh_idx,
	struct nexthop *nh
) {
	struct rte_fib *fib = get_or_create_fib(vrf_id);
	uint32_t host_order_ip = rte_be_to_cpu_32(ip);
	int ret;

	if (fib == NULL)
		return -errno;

	if (ip4_route_lookup_exact(vrf_id, ip, prefixlen) != NULL)
		return errno_set(EEXIST);

	if ((ret = rte_fib_add(fib, host_order_ip, prefixlen, nh_idx)) < 0)
		return ret;

	ip4_nexthop_incref(nh);

	return 0;
}

int ip4_route_delete(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen) {
	uint32_t host_order_ip = rte_be_to_cpu_32(ip);
	struct rte_fib *fib = get_fib(vrf_id);
	struct nexthop *nh;
	int ret;

	if (fib == NULL)
		return -errno;

	nh = ip4_route_lookup_exact(vrf_id, ip, prefixlen);
	if (nh == NULL)
		return errno_set(ENOENT);

	if ((ret = rte_fib_delete(fib, host_order_ip, prefixlen)) < 0)
		return errno_set(-ret);

	ip4_nexthop_decref(nh);

	return 0;
}

static struct api_out route4_add(const void *request, void **response) {
	const struct br_ip4_route_add_req *req = request;
	struct rte_fib *fib;
	struct nexthop *nh;
	uint32_t nh_idx;
	int ret;

	(void)response;

	nh = ip4_route_lookup_exact(req->vrf_id, req->dest.ip, req->dest.prefixlen);
	if (nh != NULL) {
		if (req->nh == nh->ip && req->exist_ok)
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	if (ip4_route_lookup(req->vrf_id, req->nh) == NULL)
		return api_out(EHOSTUNREACH, 0);

	if ((fib = get_or_create_fib(req->vrf_id)) == NULL)
		return api_out(errno, 0);

	if (ip4_nexthop_lookup_add(req->vrf_id, req->nh, &nh_idx, &nh) < 0)
		return api_out(errno, 0);

	if ((ret = rte_fib_add(fib, ntohl(req->dest.ip), req->dest.prefixlen, nh_idx)) < 0) {
		ip4_nexthop_decref(nh);
		return api_out(-ret, 0);
	}

	ip4_nexthop_incref(nh);
	nh->flags |= BR_IP4_NH_F_GATEWAY;

	return api_out(0, 0);
}

static struct api_out route4_del(const void *request, void **response) {
	const struct br_ip4_route_del_req *req = request;
	struct nexthop *nh;

	(void)response;

	if ((nh = ip4_route_lookup_exact(req->vrf_id, req->dest.ip, req->dest.prefixlen)) == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}

	if (!(nh->flags & BR_IP4_NH_F_GATEWAY))
		return api_out(EBUSY, 0);

	if (ip4_route_delete(req->vrf_id, req->dest.ip, req->dest.prefixlen) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct api_out route4_get(const void *request, void **response) {
	const struct br_ip4_route_get_req *req = request;
	struct br_ip4_route_get_resp *resp = NULL;
	struct nexthop *nh = NULL;

	nh = ip4_route_lookup(req->vrf_id, req->dest);
	if (nh == NULL)
		return api_out(ENETUNREACH, 0);

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);

	resp->nh.host = nh->ip;
	resp->nh.iface_id = nh->iface_id;
	memcpy(&resp->nh.mac, &nh->lladdr, sizeof(resp->nh.mac));
	resp->nh.flags = nh->flags;

	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out route4_list(const void *request, void **response) {
	const struct br_ip4_route_list_req *req = request;
	struct br_ip4_route_list_resp *resp = NULL;
	struct rte_fib *fib = get_fib(req->vrf_id);
	struct rte_rib_node *rn = NULL;
	struct br_ip4_route *r;
	struct rte_rib *rib;
	struct nexthop *nh;
	size_t num, len;
	uint64_t nh_idx;
	uint32_t ip;

	(void)request;

	if (fib == NULL)
		return api_out(errno, 0);

	rib = rte_fib_get_rib(fib);

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
		rte_rib_get_nh(rn, &nh_idx);
		nh = ip4_nexthop_get(nh_idx);
		rte_rib_get_ip(rn, &ip);
		rte_rib_get_depth(rn, &r->dest.prefixlen);
		r->dest.ip = htonl(ip);
		r->nh = nh->ip;
	}
	// FIXME: remove this when rte_rib_get_nxt returns a default route, if any is configured
	if ((rn = rte_rib_lookup_exact(rib, 0, 0)) != NULL) {
		r = &resp->routes[resp->n_routes++];
		rte_rib_get_nh(rn, &nh_idx);
		nh = ip4_nexthop_get(nh_idx);
		r->dest.ip = 0;
		r->dest.prefixlen = 0;
		r->nh = nh->ip;
	}
	*response = resp;

	return api_out(0, len);
}

static void route4_init(void) {
	vrf_fibs = rte_calloc(__func__, MAX_VRFS, sizeof(struct rte_fib *), RTE_CACHE_LINE_SIZE);
	if (vrf_fibs == NULL)
		ABORT("rte_calloc(vrf_fibs): %s", rte_strerror(rte_errno));
}

static void route4_fini(void) {
	for (uint16_t vrf_id = 0; vrf_id < MAX_VRFS; vrf_id++) {
		rte_fib_free(vrf_fibs[vrf_id]);
		vrf_fibs[vrf_id] = NULL;
	}
	rte_free(vrf_fibs);
	vrf_fibs = NULL;
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
