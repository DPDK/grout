// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_ip4.h>
#include <gr_ip4_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_queue.h>

#include <event2/event.h>
#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_fib.h>
#include <rte_malloc.h>
#include <rte_rib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_fib **vrf_fibs;
#define BLACKHOLE (IP4_MAX_NEXT_HOPS + 1)

static struct rte_fib_conf fib_conf = {
	.type = RTE_FIB_DIR24_8,
	.default_nh = BLACKHOLE,
	.max_routes = IP4_MAX_ROUTES,
	.rib_ext_sz = 0,
	.dir24_8 = {
		.nh_sz = RTE_FIB_DIR24_8_8B,
		.num_tbl8 = 1 << 15,
	},
};

static struct rte_fib *get_fib(uint16_t vrf_id) {
	struct rte_fib *fib;

	if (vrf_id >= IP4_MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL)
		return errno_set_null(ENONET);

	return fib;
}

static struct rte_fib *get_or_create_fib(uint16_t vrf_id) {
	struct rte_fib *fib;

	if (vrf_id >= IP4_MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL) {
		char name[64];

		snprintf(name, sizeof(name), "ip_vrf_%u", vrf_id);
		fib = rte_fib_create(name, SOCKET_ID_ANY, &fib_conf);
		if (fib == NULL)
			return errno_set_null(rte_errno);

		vrf_fibs[vrf_id] = fib;
	}

	return fib;
}

static inline uintptr_t nh_ptr_to_id(struct nexthop *nh) {
	uintptr_t id = (uintptr_t)nh;

	// rte_fib stores the nexthop ID on 8 bytes minus one bit which is used
	// to store metadata about the routing table.
	//
	// Address mappings in userspace are guaranteed on x86_64 and aarch64
	// to use at most 47 bits, leaving at least 17 bits of headroom filled
	// with zeroes.
	//
	// rte_fib_add already checks that the nexthop value does not exceed the
	// maximum allowed value. For clarity, we explicitly fail if the MSB is
	// not zero.
	if (id & GR_BIT64(63))
		ABORT("MSB is not 0, martian architecture?");

	return id;
}

static inline struct nexthop *nh_id_to_ptr(uintptr_t id) {
	return (struct nexthop *)id;
}

struct nexthop *ip4_route_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	uint32_t host_order_ip = rte_be_to_cpu_32(ip);
	struct rte_fib *fib = get_fib(vrf_id);
	uintptr_t nh_id;

	if (fib == NULL)
		return NULL;

	rte_fib_lookup_bulk(fib, &host_order_ip, &nh_id, 1);
	if (nh_id == BLACKHOLE)
		return errno_set_null(EHOSTUNREACH);

	return nh_id_to_ptr(nh_id);
}

struct nexthop *ip4_route_lookup_exact(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen) {
	uint32_t host_order_ip = rte_be_to_cpu_32(ip);
	struct rte_fib *fib = get_fib(vrf_id);
	struct rte_rib_node *rn;
	struct rte_rib *rib;
	uintptr_t nh_id;

	if (fib == NULL)
		return NULL;

	rib = rte_fib_get_rib(fib);
	rn = rte_rib_lookup_exact(rib, host_order_ip, prefixlen);
	if (rn == NULL)
		return errno_set_null(ENETUNREACH);

	rte_rib_get_nh(rn, &nh_id);
	return nh_id_to_ptr(nh_id);
}

int ip4_route_insert(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen, struct nexthop *nh) {
	struct rte_fib *fib = get_or_create_fib(vrf_id);
	uint32_t host_order_ip = rte_be_to_cpu_32(ip);
	int ret;

	ip4_nexthop_incref(nh);

	if (fib == NULL) {
		ret = -errno;
		goto fail;
	}
	if (ip4_route_lookup_exact(vrf_id, ip, prefixlen) != NULL) {
		ret = -EEXIST;
		goto fail;
	}
	if ((ret = rte_fib_add(fib, host_order_ip, prefixlen, nh_ptr_to_id(nh))) < 0)
		goto fail;

	return 0;
fail:
	ip4_nexthop_decref(nh);
	return errno_set(-ret);
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

static struct api_out route4_add(const void *request, void ** /*response*/) {
	const struct gr_ip4_route_add_req *req = request;
	uint32_t host_order_ip;
	struct rte_fib *fib;
	struct nexthop *nh;
	int ret;

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

	if ((nh = ip4_nexthop_lookup(req->vrf_id, req->nh)) == NULL)
		if ((nh = ip4_nexthop_new(req->vrf_id, GR_IFACE_ID_UNDEF, req->nh)) == NULL)
			return api_out(errno, 0);

	host_order_ip = ntohl(req->dest.ip);

	if ((ret = rte_fib_add(fib, host_order_ip, req->dest.prefixlen, nh_ptr_to_id(nh))) < 0) {
		ip4_nexthop_decref(nh);
		return api_out(-ret, 0);
	}

	ip4_nexthop_incref(nh);
	nh->flags |= GR_IP4_NH_F_GATEWAY;

	return api_out(0, 0);
}

static struct api_out route4_del(const void *request, void ** /*response*/) {
	const struct gr_ip4_route_del_req *req = request;
	struct nexthop *nh;

	if ((nh = ip4_route_lookup_exact(req->vrf_id, req->dest.ip, req->dest.prefixlen)) == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}

	if (!(nh->flags & GR_IP4_NH_F_GATEWAY))
		return api_out(EBUSY, 0);

	if (ip4_route_delete(req->vrf_id, req->dest.ip, req->dest.prefixlen) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct api_out route4_get(const void *request, void **response) {
	const struct gr_ip4_route_get_req *req = request;
	struct gr_ip4_route_get_resp *resp = NULL;
	struct nexthop *nh = NULL;

	nh = ip4_route_lookup(req->vrf_id, req->dest);
	if (nh == NULL)
		return api_out(ENETUNREACH, 0);

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);

	resp->nh.host = nh->ip;
	resp->nh.iface_id = nh->iface_id;
	resp->nh.mac = nh->lladdr;
	resp->nh.flags = nh->flags;

	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out route4_list(const void *request, void **response) {
	const struct gr_ip4_route_list_req *req = request;
	struct gr_ip4_route_list_resp *resp = NULL;
	struct rte_fib *fib = get_fib(req->vrf_id);
	struct rte_rib_node *rn = NULL;
	struct gr_ip4_route *r;
	struct rte_rib *rib;
	size_t num, len;
	uintptr_t nh_id;
	uint32_t ip;

	if (fib == NULL)
		return api_out(errno, 0);

	rib = rte_fib_get_rib(fib);

	num = 0;
	while ((rn = rte_rib_get_nxt(rib, 0, 0, rn, RTE_RIB_GET_NXT_ALL)) != NULL)
		num++;
	// FIXME: remove this when rte_rib_get_nxt returns a default route, if any is configured
	if (rte_rib_lookup_exact(rib, 0, 0) != NULL)
		num++;

	len = sizeof(*resp) + num * sizeof(struct gr_ip4_route);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	while ((rn = rte_rib_get_nxt(rib, 0, 0, rn, RTE_RIB_GET_NXT_ALL)) != NULL) {
		r = &resp->routes[resp->n_routes++];
		rte_rib_get_nh(rn, &nh_id);
		rte_rib_get_ip(rn, &ip);
		rte_rib_get_depth(rn, &r->dest.prefixlen);
		r->dest.ip = htonl(ip);
		r->nh = nh_id_to_ptr(nh_id)->ip;
	}
	// FIXME: remove this when rte_rib_get_nxt returns a default route, if any is configured
	if ((rn = rte_rib_lookup_exact(rib, 0, 0)) != NULL) {
		r = &resp->routes[resp->n_routes++];
		rte_rib_get_nh(rn, &nh_id);
		r->dest.ip = 0;
		r->dest.prefixlen = 0;
		r->nh = nh_id_to_ptr(nh_id)->ip;
	}
	*response = resp;

	return api_out(0, len);
}

static void route4_init(struct event_base *) {
	vrf_fibs = rte_calloc(
		__func__, IP4_MAX_VRFS, sizeof(struct rte_fib *), RTE_CACHE_LINE_SIZE
	);
	if (vrf_fibs == NULL)
		ABORT("rte_calloc(vrf_fibs): %s", rte_strerror(rte_errno));
}

static void route4_fini(struct event_base *) {
	for (uint16_t vrf_id = 0; vrf_id < IP4_MAX_VRFS; vrf_id++) {
		rte_fib_free(vrf_fibs[vrf_id]);
		vrf_fibs[vrf_id] = NULL;
	}
	rte_free(vrf_fibs);
	vrf_fibs = NULL;
}

void ip4_route_cleanup(struct nexthop *nh) {
	uint8_t prefixlen, local_prefixlen;
	struct rte_rib_node *rn = NULL;
	struct rte_rib *rib;
	ip4_addr_t local_ip;
	uintptr_t nh_id;
	ip4_addr_t ip;

	local_ip = nh->ip;
	local_prefixlen = nh->prefixlen;

	rib = rte_fib_get_rib(get_fib(nh->vrf_id));
	while ((rn = rte_rib_get_nxt(rib, 0, 0, rn, RTE_RIB_GET_NXT_ALL)) != NULL) {
		rte_rib_get_nh(rn, &nh_id);
		nh = nh_id_to_ptr(nh_id);

		if (nh && ip4_addr_same_subnet(nh->ip, local_ip, local_prefixlen)) {
			rte_rib_get_ip(rn, &ip);
			rte_rib_get_depth(rn, &prefixlen);
			ip = rte_cpu_to_be_32(ip);

			LOG(DEBUG,
			    "delete " IP4_ADDR_FMT "/%d via " IP4_ADDR_FMT,
			    IP4_ADDR_SPLIT(&ip),
			    prefixlen,
			    IP4_ADDR_SPLIT(&nh->ip));

			ip4_route_delete(nh->vrf_id, ip, prefixlen);
			ip4_route_delete(nh->vrf_id, ip, 32);
		}
	}

	if ((rn = rte_rib_lookup_exact(rib, 0, 0)) != NULL) {
		rte_rib_get_nh(rn, &nh_id);
		nh = nh_id_to_ptr(nh_id);

		if (nh && ip4_addr_same_subnet(nh->ip, local_ip, local_prefixlen)) {
			rte_rib_get_ip(rn, &ip);
			rte_rib_get_depth(rn, &prefixlen);
			ip = rte_cpu_to_be_32(ip);

			LOG(DEBUG,
			    "delete " IP4_ADDR_FMT "/%d via " IP4_ADDR_FMT,
			    IP4_ADDR_SPLIT(&ip),
			    prefixlen,
			    IP4_ADDR_SPLIT(&nh->ip));

			ip4_route_delete(nh->vrf_id, nh->ip, nh->prefixlen);
			ip4_route_delete(nh->vrf_id, nh->ip, 32);
		}
	}

	ip4_route_delete(nh->vrf_id, local_ip, 32);
}

static struct gr_api_handler route4_add_handler = {
	.name = "ipv4 route add",
	.request_type = GR_IP4_ROUTE_ADD,
	.callback = route4_add,
};
static struct gr_api_handler route4_del_handler = {
	.name = "ipv4 route del",
	.request_type = GR_IP4_ROUTE_DEL,
	.callback = route4_del,
};
static struct gr_api_handler route4_get_handler = {
	.name = "ipv4 route get",
	.request_type = GR_IP4_ROUTE_GET,
	.callback = route4_get,
};
static struct gr_api_handler route4_list_handler = {
	.name = "ipv4 route list",
	.request_type = GR_IP4_ROUTE_LIST,
	.callback = route4_list,
};

static struct gr_module route4_module = {
	.name = "ipv4 route",
	.init = route4_init,
	.fini = route4_fini,
	.fini_prio = 10000,
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&route4_add_handler);
	gr_register_api_handler(&route4_del_handler);
	gr_register_api_handler(&route4_get_handler);
	gr_register_api_handler(&route4_list_handler);
	gr_register_module(&route4_module);
}
