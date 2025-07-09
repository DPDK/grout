// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
#include <gr_fib4.h>
#include <gr_iface.h>
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
#include <rte_malloc.h>
#include <rte_rib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_rib **vrf_ribs;

static struct rte_rib_conf rib_conf = {
	.ext_sz = sizeof(gr_nh_origin_t),
	.max_nodes = IP4_MAX_ROUTES,
};

static struct rte_rib *get_rib(uint16_t vrf_id) {
	struct rte_rib *rib;

	if (vrf_id >= MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	rib = vrf_ribs[vrf_id];
	if (rib == NULL)
		return errno_set_null(ENONET);

	return rib;
}

static struct rte_rib *get_or_create_rib(uint16_t vrf_id) {
	struct rte_rib *rib;

	if (vrf_id >= MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	rib = vrf_ribs[vrf_id];
	if (rib == NULL) {
		char name[64];

		snprintf(name, sizeof(name), "rib4_vrf_%u", vrf_id);
		rib = rte_rib_create(name, SOCKET_ID_ANY, &rib_conf);
		if (rib == NULL)
			return errno_set_null(rte_errno);

		vrf_ribs[vrf_id] = rib;
	}

	return rib;
}

static inline uintptr_t nh_ptr_to_id(struct nexthop *nh) {
	uintptr_t id = (uintptr_t)nh;

	// rte_rib stores the nexthop ID on 8 bytes minus one bit which is used
	// to store metadata about the routing table.
	//
	// Address mappings in userspace are guaranteed on x86_64 and aarch64
	// to use at most 47 bits, leaving at least 17 bits of headroom filled
	// with zeroes.
	//
	// rte_rib_add already checks that the nexthop value does not exceed the
	// maximum allowed value. For clarity, we explicitly fail if the MSB is
	// not zero.
	if (id & GR_BIT64(63))
		ABORT("MSB is not 0, martian architecture?");

	return id;
}

static inline struct nexthop *nh_id_to_ptr(uintptr_t id) {
	return (struct nexthop *)id;
}

struct nexthop *rib4_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	struct rte_rib *rib = get_rib(vrf_id);
	struct rte_rib_node *rn;
	uintptr_t nh_id;

	if (rib == NULL)
		return NULL;

	rn = rte_rib_lookup(rib, rte_be_to_cpu_32(ip));
	if (rn == NULL)
		return errno_set_null(ENETUNREACH);

	rte_rib_get_nh(rn, &nh_id);
	return nh_id_to_ptr(nh_id);
}

struct nexthop *rib4_lookup_exact(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen) {
	struct rte_rib *rib = get_rib(vrf_id);
	struct rte_rib_node *rn;
	uintptr_t nh_id;

	if (rib == NULL)
		return NULL;

	rn = rte_rib_lookup_exact(rib, rte_be_to_cpu_32(ip), prefixlen);
	if (rn == NULL)
		return errno_set_null(ENETUNREACH);

	rte_rib_get_nh(rn, &nh_id);
	return nh_id_to_ptr(nh_id);
}

int rib4_insert(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	struct nexthop *nh
) {
	struct rte_rib *rib = get_or_create_rib(vrf_id);
	struct nexthop *existing;
	struct rte_rib_node *rn;
	gr_nh_origin_t *o;
	int ret;

	nexthop_incref(nh);

	if (rib == NULL) {
		ret = -errno;
		goto fail;
	}
	existing = rib4_lookup_exact(vrf_id, ip, prefixlen);
	if (existing != NULL) {
		ret = nexthop_equal(nh, existing) ? -EEXIST : -EBUSY;
		goto fail;
	}

	if ((rn = rte_rib_insert(rib, rte_be_to_cpu_32(ip), prefixlen)) == NULL) {
		ret = -rte_errno;
		goto fail;
	}

	rte_rib_set_nh(rn, nh_ptr_to_id(nh));
	o = rte_rib_get_ext(rn);
	*o = origin;
	fib4_insert(vrf_id, ip, prefixlen, nh);
	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP_ROUTE_ADD,
			&(struct gr_ip4_route) {
				{ip, prefixlen},
				nh->base,
				origin,
			}
		);
	}

	return 0;
fail:
	nexthop_decref(nh);
	return errno_set(-ret);
}

int rib4_delete(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen, gr_nh_type_t nh_type) {
	struct rte_rib *rib = get_rib(vrf_id);
	gr_nh_origin_t *o, origin;
	struct rte_rib_node *rn;
	struct nexthop *nh;
	uintptr_t nh_id;

	if (rib == NULL)
		return -errno;

	rn = rte_rib_lookup_exact(rib, rte_be_to_cpu_32(ip), prefixlen);
	if (rn == NULL)
		return errno_set(ENOENT);

	o = rte_rib_get_ext(rn);
	origin = *o;
	rte_rib_get_nh(rn, &nh_id);
	nh = nh_id_to_ptr(nh_id);
	if (nh->type != nh_type)
		return errno_set(EINVAL);

	rte_rib_remove(rib, rte_be_to_cpu_32(ip), prefixlen);
	fib4_remove(vrf_id, ip, prefixlen);

	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP_ROUTE_DEL,
			&(struct gr_ip4_route) {
				{ip, prefixlen},
				nh->base,
				origin,
			}
		);
	}
	nexthop_decref(nh);

	return 0;
}

static struct api_out route4_add(const void *request, void ** /*response*/) {
	const struct gr_ip4_route_add_req *req = request;
	struct nexthop *nh;
	int ret;

	if (req->origin == GR_NH_ORIGIN_INTERNAL)
		return api_out(EINVAL, 0);

	if (req->nh_id != GR_NH_ID_UNSET) {
		nh = nexthop_lookup_by_id(req->nh_id);
		if (nh == NULL)
			return api_out(ENOENT, 0);
	} else {
		// ensure route gateway is reachable
		if ((nh = rib4_lookup(req->vrf_id, req->nh)) == NULL)
			return api_out(EHOSTUNREACH, 0);

		// if the route gateway is reachable via a prefix route,
		// create a new unresolved nexthop
		if (nh->ipv4 != req->nh) {
			nh = nexthop_new(&(struct gr_nexthop) {
				.type = GR_NH_T_L3,
				.af = GR_AF_IP4,
				.flags = GR_NH_F_GATEWAY,
				.vrf_id = req->vrf_id,
				.iface_id = nh->iface_id,
				.ipv4 = req->nh,
				.origin = req->origin,
			});
			if (nh == NULL)
				return api_out(errno, 0);
		}
	}

	// if route insert fails, the created nexthop will be freed
	ret = rib4_insert(req->vrf_id, req->dest.ip, req->dest.prefixlen, req->origin, nh);
	if (ret == -EEXIST && req->exist_ok)
		ret = 0;

	return api_out(-ret, 0);
}

static struct api_out route4_del(const void *request, void ** /*response*/) {
	const struct gr_ip4_route_del_req *req = request;
	int ret;

	ret = rib4_delete(req->vrf_id, req->dest.ip, req->dest.prefixlen, GR_NH_T_L3);
	if (ret == -ENOENT && req->missing_ok)
		ret = 0;

	return api_out(-ret, 0);
}

static struct api_out route4_get(const void *request, void **response) {
	const struct gr_ip4_route_get_req *req = request;
	struct gr_ip4_route_get_resp *resp = NULL;
	const struct nexthop *nh = NULL;

	nh = rib4_lookup(req->vrf_id, req->dest);
	if (nh == NULL)
		return api_out(ENETUNREACH, 0);

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);

	resp->nh = nh->base;
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static int route4_count(uint16_t vrf_id) {
	struct rte_rib_node *rn = NULL;
	gr_nh_origin_t *origin;
	struct rte_rib *rib;
	int num;

	rib = get_rib(vrf_id);
	if (rib == NULL)
		return -errno;

	num = 0;
	while ((rn = rte_rib_get_nxt(rib, 0, 0, rn, RTE_RIB_GET_NXT_ALL)) != NULL) {
		origin = rte_rib_get_ext(rn);
		if (*origin != GR_NH_ORIGIN_INTERNAL)
			num++;
	}
	// FIXME: remove this when rte_rib_get_nxt returns a default route, if any is configured
	if ((rn = rte_rib_lookup_exact(rib, 0, 0)) != NULL) {
		origin = rte_rib_get_ext(rn);
		if (*origin != GR_NH_ORIGIN_INTERNAL)
			num++;
	}

	return num;
}

static void route4_rib_to_api(struct gr_ip4_route_list_resp *resp, uint16_t vrf_id) {
	struct rte_rib_node *rn = NULL;
	struct gr_ip4_route *r;
	gr_nh_origin_t *origin;
	struct rte_rib *rib;
	uintptr_t nh_id;
	uint32_t ip;

	rib = get_rib(vrf_id);
	assert(rib != NULL);

	while ((rn = rte_rib_get_nxt(rib, 0, 0, rn, RTE_RIB_GET_NXT_ALL)) != NULL) {
		origin = rte_rib_get_ext(rn);
		if (*origin == GR_NH_ORIGIN_INTERNAL)
			continue;
		r = &resp->routes[resp->n_routes++];
		rte_rib_get_nh(rn, &nh_id);
		rte_rib_get_ip(rn, &ip);
		rte_rib_get_depth(rn, &r->dest.prefixlen);
		r->dest.ip = htonl(ip);
		r->nh = nh_id_to_ptr(nh_id)->base;
		r->origin = *origin;
	}
	// FIXME: remove this when rte_rib_get_nxt returns a default route, if any is configured
	if ((rn = rte_rib_lookup_exact(rib, 0, 0)) != NULL) {
		origin = rte_rib_get_ext(rn);
		if (*origin == GR_NH_ORIGIN_INTERNAL)
			return;
		r = &resp->routes[resp->n_routes++];
		rte_rib_get_nh(rn, &nh_id);
		r->dest.ip = 0;
		r->dest.prefixlen = 0;
		r->nh = nh_id_to_ptr(nh_id)->base;
		r->origin = *origin;
	}
}

static struct api_out route4_list(const void *request, void **response) {
	const struct gr_ip4_route_list_req *req = request;
	struct gr_ip4_route_list_resp *resp = NULL;
	size_t num, len;
	int n;

	if (req->vrf_id == UINT16_MAX) {
		num = 0;
		for (uint16_t v = 0; v < MAX_VRFS; v++) {
			if (vrf_ribs[v] == NULL)
				continue;
			if ((n = route4_count(v)) < 0)
				return api_out(errno, 0);
			num += n;
		}
	} else {
		if ((n = route4_count(req->vrf_id)) < 0)
			return api_out(errno, 0);
		num = n;
	}

	len = sizeof(*resp) + num * sizeof(struct gr_ip4_route);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	if (req->vrf_id == UINT16_MAX) {
		for (uint16_t v = 0; v < MAX_VRFS; v++) {
			if (vrf_ribs[v] == NULL)
				continue;
			route4_rib_to_api(resp, v);
		}
	} else {
		route4_rib_to_api(resp, req->vrf_id);
	}

	*response = resp;

	return api_out(0, len);
}

static void route4_init(struct event_base *) {
	vrf_ribs = rte_calloc(__func__, MAX_VRFS, sizeof(struct rte_rib *), RTE_CACHE_LINE_SIZE);
	if (vrf_ribs == NULL)
		ABORT("rte_calloc(vrf_ribs): %s", rte_strerror(rte_errno));
}

static void route4_fini(struct event_base *) {
	for (uint16_t vrf_id = 0; vrf_id < MAX_VRFS; vrf_id++) {
		rte_rib_free(vrf_ribs[vrf_id]);
		vrf_ribs[vrf_id] = NULL;
	}
	rte_free(vrf_ribs);
	vrf_ribs = NULL;
}

void rib4_cleanup(struct nexthop *nh) {
	uint8_t prefixlen, local_prefixlen;
	struct rte_rib_node *rn = NULL;
	struct rte_rib *rib;
	ip4_addr_t local_ip;
	uintptr_t nh_id;
	ip4_addr_t ip;

	local_ip = nh->ipv4;
	local_prefixlen = nh->prefixlen;

	if (nh->flags & (GR_NH_F_LOCAL | GR_NH_F_LINK))
		rib4_delete(nh->vrf_id, nh->ipv4, nh->prefixlen, nh->type);
	else
		rib4_delete(nh->vrf_id, nh->ipv4, 32, nh->type);

	rib = get_rib(nh->vrf_id);
	while ((rn = rte_rib_get_nxt(rib, 0, 0, rn, RTE_RIB_GET_NXT_ALL)) != NULL) {
		rte_rib_get_nh(rn, &nh_id);
		nh = nh_id_to_ptr(nh_id);

		if (nh && ip4_addr_same_subnet(nh->ipv4, local_ip, local_prefixlen)) {
			rte_rib_get_ip(rn, &ip);
			rte_rib_get_depth(rn, &prefixlen);
			ip = rte_cpu_to_be_32(ip);

			LOG(DEBUG,
			    "delete %s " IP4_F "/%hhu via " IP4_F,
			    gr_nh_type_name(&nh->base),
			    &ip,
			    prefixlen,
			    &nh->ipv4);

			rib4_delete(nh->vrf_id, ip, prefixlen, nh->type);
			rib4_delete(nh->vrf_id, ip, 32, nh->type);
		}
	}

	if ((rn = rte_rib_lookup_exact(rib, 0, 0)) != NULL) {
		rte_rib_get_nh(rn, &nh_id);
		nh = nh_id_to_ptr(nh_id);

		if (nh && ip4_addr_same_subnet(nh->ipv4, local_ip, local_prefixlen)) {
			rte_rib_get_ip(rn, &ip);
			rte_rib_get_depth(rn, &prefixlen);
			ip = rte_cpu_to_be_32(ip);

			LOG(DEBUG,
			    "delete %s " IP4_F "/%hhu via " IP4_F,
			    gr_nh_type_name(&nh->base),
			    &ip,
			    prefixlen,
			    &nh->ipv4);

			rib4_delete(nh->vrf_id, nh->ipv4, nh->prefixlen, nh->type);
			rib4_delete(nh->vrf_id, nh->ipv4, 32, nh->type);
		}
	}
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

static struct gr_event_serializer route_serializer = {
	.size = sizeof(struct gr_ip4_route),
	.ev_count = 2,
	.ev_types = {GR_EVENT_IP_ROUTE_ADD, GR_EVENT_IP_ROUTE_DEL},
};

static struct gr_module route4_module = {
	.name = "ipv4 route",
	.depends_on = "fib4",
	.init = route4_init,
	.fini = route4_fini,
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&route4_add_handler);
	gr_register_api_handler(&route4_del_handler);
	gr_register_api_handler(&route4_get_handler);
	gr_register_api_handler(&route4_list_handler);
	gr_event_register_serializer(&route_serializer);
	gr_register_module(&route4_module);
}
