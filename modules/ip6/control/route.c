// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_ip6.h>
#include <gr_ip6_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_queue.h>

#include <event2/event.h>
#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_fib6.h>
#include <rte_malloc.h>
#include <rte_rib6.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_fib6 **vrf_fibs;
#define BLACKHOLE (IP6_MAX_NEXT_HOPS + 1)

static struct rte_fib6_conf fib6_conf = {
	.type = RTE_FIB6_TRIE,
	.default_nh = BLACKHOLE,
	.max_routes = IP6_MAX_ROUTES,
	.rib_ext_sz = 0,
	.trie = {
		.nh_sz = RTE_FIB6_TRIE_8B,
		.num_tbl8 = 1 << 15,
	},
};

static struct rte_fib6 *get_fib6(uint16_t vrf_id) {
	struct rte_fib6 *fib;

	if (vrf_id >= IP6_MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL)
		return errno_set_null(ENONET);

	return fib;
}

static struct rte_fib6 *get_or_create_fib6(uint16_t vrf_id) {
	struct rte_fib6 *fib;

	if (vrf_id >= IP6_MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL) {
		char name[64];

		snprintf(name, sizeof(name), "ip6_vrf_%u", vrf_id);
		fib = rte_fib6_create(name, SOCKET_ID_ANY, &fib6_conf);
		if (fib == NULL)
			return errno_set_null(rte_errno);

		vrf_fibs[vrf_id] = fib;
	}

	return fib;
}

static inline uintptr_t nh_ptr_to_id(struct nexthop6 *nh) {
	uintptr_t id = (uintptr_t)nh;

	// rte_fib6 stores the nexthop ID on 8 bytes minus one bit which is used
	// to store metadata about the routing table.
	//
	// Address mappings in userspace are guaranteed on x86_64 and aarch64
	// to use at most 47 bits, leaving at least 17 bits of headroom filled
	// with zeroes.
	//
	// rte_fib6_add already checks that the nexthop value does not exceed the
	// maximum allowed value. For clarity, we explicitly fail if the MSB is
	// not zero.
	if (id & GR_BIT64(63))
		ABORT("MSB is not 0, martian architecture?");

	return id;
}

static inline struct nexthop6 *nh_id_to_ptr(uintptr_t id) {
	return (struct nexthop6 *)id;
}

struct nexthop6 *ip6_route_lookup(uint16_t vrf_id, const struct rte_ipv6_addr *ip) {
	struct rte_fib6 *fib6 = get_fib6(vrf_id);
	uintptr_t nh_id;

	if (fib6 == NULL)
		return NULL;

	rte_fib6_lookup_bulk(fib6, ip, &nh_id, 1);
	if (nh_id == BLACKHOLE)
		return errno_set_null(EHOSTUNREACH);

	return nh_id_to_ptr(nh_id);
}

struct nexthop6 *
ip6_route_lookup_exact(uint16_t vrf_id, const struct rte_ipv6_addr *ip, uint8_t prefixlen) {
	struct rte_fib6 *fib = get_fib6(vrf_id);
	struct rte_rib6_node *rn;
	struct rte_rib6 *rib6;
	uintptr_t nh_id;

	if (fib == NULL)
		return NULL;

	rib6 = rte_fib6_get_rib(fib);
	rn = rte_rib6_lookup_exact(rib6, ip, prefixlen);
	if (rn == NULL)
		return errno_set_null(ENETUNREACH);

	rte_rib6_get_nh(rn, &nh_id);
	return nh_id_to_ptr(nh_id);
}

int ip6_route_insert(
	uint16_t vrf_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	struct nexthop6 *nh
) {
	struct rte_fib6 *fib = get_or_create_fib6(vrf_id);
	int ret;

	ip6_nexthop_incref(nh);

	if (fib == NULL) {
		ret = -errno;
		goto fail;
	}
	if (ip6_route_lookup_exact(vrf_id, ip, prefixlen) != NULL) {
		ret = -EEXIST;
		goto fail;
	}
	if ((ret = rte_fib6_add(fib, ip, prefixlen, nh_ptr_to_id(nh))) < 0)
		goto fail;

	return 0;
fail:
	ip6_nexthop_decref(nh);
	return errno_set(-ret);
}

int ip6_route_delete(uint16_t vrf_id, const struct rte_ipv6_addr *ip, uint8_t prefixlen) {
	struct rte_fib6 *fib = get_fib6(vrf_id);
	struct nexthop6 *nh;
	int ret;

	if (fib == NULL)
		return -errno;

	nh = ip6_route_lookup_exact(vrf_id, ip, prefixlen);
	if (nh == NULL)
		return errno_set(ENOENT);

	if ((ret = rte_fib6_delete(fib, ip, prefixlen)) < 0)
		return errno_set(-ret);

	ip6_nexthop_decref(nh);

	return 0;
}

static struct api_out route6_add(const void *request, void ** /*response*/) {
	const struct gr_ip6_route_add_req *req = request;
	struct rte_fib6 *fib6;
	struct nexthop6 *nh;
	int ret;

	nh = ip6_route_lookup_exact(req->vrf_id, &req->dest.ip, req->dest.prefixlen);
	if (nh != NULL) {
		if (rte_ipv6_addr_eq(&req->nh, &nh->ip) && req->exist_ok)
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	if (ip6_route_lookup(req->vrf_id, &req->nh) == NULL)
		return api_out(EHOSTUNREACH, 0);

	if ((fib6 = get_or_create_fib6(req->vrf_id)) == NULL)
		return api_out(errno, 0);

	if ((nh = ip6_nexthop_lookup(req->vrf_id, &req->nh)) == NULL)
		if ((nh = ip6_nexthop_new(req->vrf_id, GR_IFACE_ID_UNDEF, &req->nh)) == NULL)
			return api_out(errno, 0);

	if ((ret = rte_fib6_add(fib6, &req->dest.ip, req->dest.prefixlen, nh_ptr_to_id(nh))) < 0) {
		ip6_nexthop_decref(nh);
		return api_out(-ret, 0);
	}

	ip6_nexthop_incref(nh);
	nh->flags |= GR_IP6_NH_F_GATEWAY;

	return api_out(0, 0);
}

static struct api_out route6_del(const void *request, void ** /*response*/) {
	const struct gr_ip6_route_del_req *req = request;
	struct nexthop6 *nh;

	if ((nh = ip6_route_lookup_exact(req->vrf_id, &req->dest.ip, req->dest.prefixlen))
	    == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}

	if (!(nh->flags & GR_IP6_NH_F_GATEWAY))
		return api_out(EBUSY, 0);

	if (ip6_route_delete(req->vrf_id, &req->dest.ip, req->dest.prefixlen) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct api_out route6_get(const void *request, void **response) {
	const struct gr_ip6_route_get_req *req = request;
	struct gr_ip6_route_get_resp *resp = NULL;
	struct nexthop6 *nh = NULL;

	nh = ip6_route_lookup(req->vrf_id, &req->dest);
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

static struct api_out route6_list(const void *request, void **response) {
	const struct gr_ip6_route_list_req *req = request;
	struct gr_ip6_route_list_resp *resp = NULL;
	struct rte_fib6 *fib = get_fib6(req->vrf_id);
	struct rte_rib6_node *rn = NULL;
	struct rte_ipv6_addr zero = {0};
	struct gr_ip6_route *r;
	struct rte_rib6 *rib;
	size_t num, len;
	uintptr_t nh_id;

	if (fib == NULL)
		return api_out(errno, 0);

	rib = rte_fib6_get_rib(fib);

	num = 0;
	while ((rn = rte_rib6_get_nxt(rib, &zero, 0, rn, RTE_RIB6_GET_NXT_ALL)) != NULL)
		num++;
	// FIXME: remove this when rte_rib6_get_nxt returns a default route, if any is configured
	if (rte_rib6_lookup_exact(rib, &zero, 0) != NULL)
		num++;

	len = sizeof(*resp) + num * sizeof(struct gr_ip6_route);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	while ((rn = rte_rib6_get_nxt(rib, &zero, 0, rn, RTE_RIB6_GET_NXT_ALL)) != NULL) {
		r = &resp->routes[resp->n_routes++];
		rte_rib6_get_nh(rn, &nh_id);
		rte_rib6_get_ip(rn, &r->dest.ip);
		rte_rib6_get_depth(rn, &r->dest.prefixlen);
		r->nh = nh_id_to_ptr(nh_id)->ip;
	}
	// FIXME: remove this when rte_rib6_get_nxt returns a default route, if any is configured
	if ((rn = rte_rib6_lookup_exact(rib, &zero, 0)) != NULL) {
		r = &resp->routes[resp->n_routes++];
		rte_rib6_get_nh(rn, &nh_id);
		memset(&r->dest, 0, sizeof(r->dest));
		r->nh = nh_id_to_ptr(nh_id)->ip;
	}
	*response = resp;

	return api_out(0, len);
}

static void route6_init(struct event_base *) {
	vrf_fibs = rte_calloc(
		__func__, IP6_MAX_VRFS, sizeof(struct rte_fib6 *), RTE_CACHE_LINE_SIZE
	);
	if (vrf_fibs == NULL)
		ABORT("rte_calloc(vrf_fib6s): %s", rte_strerror(rte_errno));
}

static void route6_fini(struct event_base *) {
	for (uint16_t vrf_id = 0; vrf_id < IP6_MAX_VRFS; vrf_id++) {
		rte_fib6_free(vrf_fibs[vrf_id]);
		vrf_fibs[vrf_id] = NULL;
	}
	rte_free(vrf_fibs);
	vrf_fibs = NULL;
}

void ip6_route_cleanup(struct nexthop6 *nh) {
	struct rte_ipv6_addr local_ip, ip;
	struct rte_rib6_node *rn = NULL;
	uint8_t depth, local_depth;
	struct rte_rib6 *rib;
	uintptr_t nh_id;

	ip6_route_delete(nh->vrf_id, &nh->ip, RTE_IPV6_MAX_DEPTH);
	local_ip = nh->ip;
	local_depth = nh->prefixlen;

	rib = rte_fib6_get_rib(get_fib6(nh->vrf_id));
	while ((rn = rte_rib6_get_nxt(rib, 0, 0, rn, RTE_RIB6_GET_NXT_ALL)) != NULL) {
		rte_rib6_get_nh(rn, &nh_id);
		nh = nh_id_to_ptr(nh_id);

		if (nh && rte_ipv6_addr_eq_prefix(&nh->ip, &local_ip, local_depth)) {
			rte_rib6_get_ip(rn, &ip);
			rte_rib6_get_depth(rn, &depth);

			LOG(DEBUG,
			    "delete " IPV6_ADDR_FMT "/%d via " IPV6_ADDR_FMT,
			    IPV6_ADDR_SPLIT(&ip),
			    depth,
			    IPV6_ADDR_SPLIT(&nh->ip));

			ip6_route_delete(nh->vrf_id, &ip, depth);
			ip6_route_delete(nh->vrf_id, &ip, RTE_IPV6_MAX_DEPTH);
		}
	}

	if ((rn = rte_rib6_lookup_exact(rib, 0, 0)) != NULL) {
		rte_rib6_get_nh(rn, &nh_id);
		nh = nh_id_to_ptr(nh_id);

		if (nh && rte_ipv6_addr_eq_prefix(&nh->ip, &local_ip, local_depth)) {
			rte_rib6_get_ip(rn, &ip);
			rte_rib6_get_depth(rn, &depth);

			LOG(DEBUG,
			    "delete " IPV6_ADDR_FMT "/%d via " IPV6_ADDR_FMT,
			    IPV6_ADDR_SPLIT(&ip),
			    depth,
			    IPV6_ADDR_SPLIT(&nh->ip));

			ip6_route_delete(nh->vrf_id, &nh->ip, nh->prefixlen);
			ip6_route_delete(nh->vrf_id, &nh->ip, RTE_IPV6_MAX_DEPTH);
		}
	}
}

static struct gr_api_handler route6_add_handler = {
	.name = "ipv6 route add",
	.request_type = GR_IP6_ROUTE_ADD,
	.callback = route6_add,
};
static struct gr_api_handler route6_del_handler = {
	.name = "ipv6 route del",
	.request_type = GR_IP6_ROUTE_DEL,
	.callback = route6_del,
};
static struct gr_api_handler route6_get_handler = {
	.name = "ipv6 route get",
	.request_type = GR_IP6_ROUTE_GET,
	.callback = route6_get,
};
static struct gr_api_handler route6_list_handler = {
	.name = "ipv6 route list",
	.request_type = GR_IP6_ROUTE_LIST,
	.callback = route6_list,
};

static struct gr_module route6_module = {
	.name = "ipv6 route",
	.init = route6_init,
	.fini = route6_fini,
	.fini_prio = 10000,
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&route6_add_handler);
	gr_register_api_handler(&route6_del_handler);
	gr_register_api_handler(&route6_get_handler);
	gr_register_api_handler(&route6_list_handler);
	gr_register_module(&route6_module);
}
