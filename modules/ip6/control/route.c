// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_fib6.h>
#include <gr_iface.h>
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
#include <rte_malloc.h>
#include <rte_rib6.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_rib6 **vrf_ribs;

static struct rte_rib6_conf rib6_conf = {
	.max_nodes = IP6_MAX_ROUTES,
};

static void route_push_notification(
	ip6_event_t id,
	const struct rte_ipv6_addr *ip,
	const int prefixlen,
	const struct nexthop *nh
) {
	struct gr_ip6_route api_route = {
		.dest.ip = *ip,
		.dest.prefixlen = prefixlen,
		.nh = nh->ipv6,
	};

	gr_api_push_notification(id, sizeof(api_route), &api_route);
}

static struct rte_rib6 *get_rib6(uint16_t vrf_id) {
	struct rte_rib6 *rib;

	if (vrf_id >= MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	rib = vrf_ribs[vrf_id];
	if (rib == NULL)
		return errno_set_null(ENONET);

	return rib;
}

static struct rte_rib6 *get_or_create_rib6(uint16_t vrf_id) {
	struct rte_rib6 *rib;

	if (vrf_id >= MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	rib = vrf_ribs[vrf_id];
	if (rib == NULL) {
		char name[64];

		snprintf(name, sizeof(name), "rib6_vrf_%u", vrf_id);
		rib = rte_rib6_create(name, SOCKET_ID_ANY, &rib6_conf);
		if (rib == NULL)
			return errno_set_null(rte_errno);

		vrf_ribs[vrf_id] = rib;
	}

	return rib;
}

static inline uintptr_t nh_ptr_to_id(struct nexthop *nh) {
	uintptr_t id = (uintptr_t)nh;

	// rte_rib6 stores the nexthop ID on 8 bytes minus one bit which is used
	// to store metadata about the routing table.
	//
	// Address mappings in userspace are guaranteed on x86_64 and aarch64
	// to use at most 47 bits, leaving at least 17 bits of headroom filled
	// with zeroes.
	//
	// rte_rib6_add already checks that the nexthop value does not exceed the
	// maximum allowed value. For clarity, we explicitly fail if the MSB is
	// not zero.
	if (id & GR_BIT64(63))
		ABORT("MSB is not 0, martian architecture?");

	return id;
}

static inline struct nexthop *nh_id_to_ptr(uintptr_t id) {
	return (struct nexthop *)id;
}

struct nexthop *rib6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip) {
	struct rte_rib6 *rib6 = get_rib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	struct rte_rib6_node *rn;
	struct rte_ipv6_addr tmp;
	uintptr_t nh_id;

	if (rib6 == NULL)
		return NULL;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	rn = rte_rib6_lookup(rib6, scoped_ip);
	if (rn == NULL)
		return errno_set_null(ENETUNREACH);

	rte_rib6_get_nh(rn, &nh_id);
	return nh_id_to_ptr(nh_id);
}

static struct nexthop *rib6_lookup_exact(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen
) {
	struct rte_rib6 *rib6 = get_rib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	struct rte_rib6_node *rn;
	struct rte_ipv6_addr tmp;
	uintptr_t nh_id;

	if (rib6 == NULL)
		return NULL;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	rn = rte_rib6_lookup_exact(rib6, scoped_ip, prefixlen);
	if (rn == NULL)
		return errno_set_null(ENETUNREACH);

	rte_rib6_get_nh(rn, &nh_id);
	return nh_id_to_ptr(nh_id);
}

int rib6_insert(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	struct nexthop *nh
) {
	struct rte_rib6 *rib = get_or_create_rib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	struct rte_ipv6_addr tmp;
	struct rte_rib6_node *rn;
	int ret;

	nexthop_incref(nh);

	if (rib == NULL) {
		ret = -errno;
		goto fail;
	}
	if (rib6_lookup_exact(vrf_id, iface_id, ip, prefixlen) != NULL) {
		ret = -EEXIST;
		goto fail;
	}

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	if ((rn = rte_rib6_insert(rib, scoped_ip, prefixlen)) == NULL) {
		ret = -rte_errno;
		goto fail;
	}

	rte_rib6_set_nh(rn, nh_ptr_to_id(nh));
	fib6_insert(vrf_id, iface_id, scoped_ip, prefixlen, nh);

	route_push_notification(IP6_EVENT_ROUTE_ADD, ip, prefixlen, nh);
	return 0;
fail:
	nexthop_decref(nh);
	return errno_set(-ret);
}

int rib6_delete(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen
) {
	struct rte_rib6 *rib = get_rib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	struct rte_ipv6_addr tmp;
	struct nexthop *nh;

	if (rib == NULL)
		return -errno;

	nh = rib6_lookup_exact(vrf_id, iface_id, ip, prefixlen);
	if (nh == NULL)
		return errno_set(ENOENT);

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	rte_rib6_remove(rib, scoped_ip, prefixlen);

	route_push_notification(IP6_EVENT_ROUTE_DEL, ip, prefixlen, nh);
	nexthop_decref(nh);

	return 0;
}

static struct api_out route6_add(const void *request, void ** /*response*/) {
	const struct gr_ip6_route_add_req *req = request;
	struct nexthop *nh;
	int ret;

	// ensure route gateway is reachable
	if ((nh = rib6_lookup(req->vrf_id, GR_IFACE_ID_UNDEF, &req->nh)) == NULL)
		return api_out(EHOSTUNREACH, 0);

	// if the route gateway is reachable via a prefix route,
	// create a new unresolved nexthop
	if (!rte_ipv6_addr_eq(&nh->ipv6, &req->nh)) {
		if ((nh = nh6_new(req->vrf_id, nh->iface_id, &req->nh)) == NULL)
			return api_out(errno, 0);
		nh->flags |= GR_NH_F_GATEWAY;
	}

	// if route insert fails, the created nexthop will be freed
	ret = rib6_insert(req->vrf_id, nh->iface_id, &req->dest.ip, req->dest.prefixlen, nh);
	if (ret == -EEXIST && req->exist_ok)
		ret = 0;

	return api_out(-ret, 0);
}

static struct api_out route6_del(const void *request, void ** /*response*/) {
	const struct gr_ip6_route_del_req *req = request;
	struct nexthop *nh;

	if ((nh = rib6_lookup_exact(
		     req->vrf_id, GR_IFACE_ID_UNDEF, &req->dest.ip, req->dest.prefixlen
	     ))
	    == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}

	if (!(nh->flags & GR_NH_F_GATEWAY))
		return api_out(EBUSY, 0);

	if (rib6_delete(req->vrf_id, nh->iface_id, &req->dest.ip, req->dest.prefixlen) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct api_out route6_get(const void *request, void **response) {
	const struct gr_ip6_route_get_req *req = request;
	struct gr_ip6_route_get_resp *resp = NULL;
	const struct nexthop *nh = NULL;

	nh = fib6_lookup(req->vrf_id, GR_IFACE_ID_UNDEF, &req->dest);
	if (nh == NULL)
		return api_out(ENETUNREACH, 0);

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);

	resp->nh.ipv6 = nh->ipv6;
	resp->nh.iface_id = nh->iface_id;
	resp->nh.mac = nh->lladdr;
	resp->nh.flags = nh->flags;

	*response = resp;

	return api_out(0, sizeof(*resp));
}

static int route6_count(uint16_t vrf_id) {
	struct rte_ipv6_addr zero = RTE_IPV6_ADDR_UNSPEC;
	struct rte_rib6_node *rn = NULL;
	struct rte_rib6 *rib;
	int num;

	rib = get_rib6(vrf_id);
	if (rib == NULL)
		return -errno;

	num = 0;
	while ((rn = rte_rib6_get_nxt(rib, &zero, 0, rn, RTE_RIB6_GET_NXT_ALL)) != NULL)
		num++;
	// check if there is a default route configured
	if (rte_rib6_lookup_exact(rib, &zero, 0) != NULL)
		num++;

	return num;
}

static void route6_rib_to_api(struct gr_ip6_route_list_resp *resp, uint16_t vrf_id) {
	struct rte_ipv6_addr zero = RTE_IPV6_ADDR_UNSPEC;
	struct rte_rib6_node *rn = NULL;
	struct rte_ipv6_addr tmp;
	struct gr_ip6_route *r;
	struct rte_rib6 *rib;
	uintptr_t nh_id;

	rib = get_rib6(vrf_id);
	assert(rib != NULL);

	while ((rn = rte_rib6_get_nxt(rib, &zero, 0, rn, RTE_RIB6_GET_NXT_ALL)) != NULL) {
		r = &resp->routes[resp->n_routes++];
		rte_rib6_get_nh(rn, &nh_id);
		rte_rib6_get_ip(rn, &r->dest.ip);
		rte_rib6_get_depth(rn, &r->dest.prefixlen);
		r->nh = nh_id_to_ptr(nh_id)->ipv6;
		r->vrf_id = vrf_id;
		r->dest.ip = *addr6_linklocal_unscope(&r->dest.ip, &tmp);
	}
	// check if there is a default route configured
	if ((rn = rte_rib6_lookup_exact(rib, &zero, 0)) != NULL) {
		r = &resp->routes[resp->n_routes++];
		rte_rib6_get_nh(rn, &nh_id);
		memset(&r->dest, 0, sizeof(r->dest));
		r->nh = nh_id_to_ptr(nh_id)->ipv6;
		r->vrf_id = vrf_id;
	}
}

static struct api_out route6_list(const void *request, void **response) {
	const struct gr_ip6_route_list_req *req = request;
	struct gr_ip6_route_list_resp *resp = NULL;
	size_t num, len;
	int n;

	if (req->vrf_id == UINT16_MAX) {
		num = 0;
		for (uint16_t v = 0; v < MAX_VRFS; v++) {
			if (vrf_ribs[v] == NULL)
				continue;
			if ((n = route6_count(v)) < 0)
				return api_out(errno, 0);
			num += n;
		}
	} else {
		if ((n = route6_count(req->vrf_id)) < 0)
			return api_out(errno, 0);
		num = n;
	}

	len = sizeof(*resp) + num * sizeof(struct gr_ip6_route);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	if (req->vrf_id == UINT16_MAX) {
		for (uint16_t v = 0; v < MAX_VRFS; v++) {
			if (vrf_ribs[v] == NULL)
				continue;
			route6_rib_to_api(resp, v);
		}
	} else {
		route6_rib_to_api(resp, req->vrf_id);
	}

	*response = resp;

	return api_out(0, len);
}

static void route6_init(struct event_base *) {
	vrf_ribs = rte_calloc(__func__, MAX_VRFS, sizeof(struct rte_rib6 *), RTE_CACHE_LINE_SIZE);
	if (vrf_ribs == NULL)
		ABORT("rte_calloc(vrf_rib6s): %s", rte_strerror(rte_errno));
}

static void route6_fini(struct event_base *) {
	for (uint16_t vrf_id = 0; vrf_id < MAX_VRFS; vrf_id++) {
		rte_rib6_free(vrf_ribs[vrf_id]);
		vrf_ribs[vrf_id] = NULL;
	}
	rte_free(vrf_ribs);
	vrf_ribs = NULL;
}

void rib6_cleanup(struct nexthop *nh) {
	struct rte_ipv6_addr local_ip, ip;
	struct rte_rib6_node *rn = NULL;
	uint8_t depth, local_depth;
	struct rte_rib6 *rib;
	uintptr_t nh_id;

	rib6_delete(nh->vrf_id, nh->iface_id, &nh->ipv6, RTE_IPV6_MAX_DEPTH);
	local_ip = nh->ipv6;
	local_depth = nh->prefixlen;

	rib = get_rib6(nh->vrf_id);
	while ((rn = rte_rib6_get_nxt(rib, 0, 0, rn, RTE_RIB6_GET_NXT_ALL)) != NULL) {
		rte_rib6_get_nh(rn, &nh_id);
		nh = nh_id_to_ptr(nh_id);

		if (nh && rte_ipv6_addr_eq_prefix(&nh->ipv6, &local_ip, local_depth)) {
			rte_rib6_get_ip(rn, &ip);
			rte_rib6_get_depth(rn, &depth);

			LOG(DEBUG, "delete " IP6_F "/%hhu via " IP6_F, &ip, depth, &nh->ipv6);

			rib6_delete(nh->vrf_id, nh->iface_id, &ip, depth);
			rib6_delete(nh->vrf_id, nh->iface_id, &ip, RTE_IPV6_MAX_DEPTH);
		}
	}

	if ((rn = rte_rib6_lookup_exact(rib, 0, 0)) != NULL) {
		rte_rib6_get_nh(rn, &nh_id);
		nh = nh_id_to_ptr(nh_id);

		if (nh && rte_ipv6_addr_eq_prefix(&nh->ipv6, &local_ip, local_depth)) {
			rte_rib6_get_ip(rn, &ip);
			rte_rib6_get_depth(rn, &depth);

			LOG(DEBUG, "delete " IP6_F "/%hhu via " IP6_F, &ip, depth, &nh->ipv6);

			rib6_delete(nh->vrf_id, nh->iface_id, &nh->ipv6, nh->prefixlen);
			rib6_delete(nh->vrf_id, nh->iface_id, &nh->ipv6, RTE_IPV6_MAX_DEPTH);
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
