// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
#include <gr_fib6.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_ip6.h>
#include <gr_ip6_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_queue.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_rib6.h>
#include <rte_telemetry.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_rib6 **vrf_ribs;
static struct rib6_stats stats[GR_MAX_VRFS];

static struct rte_rib6_conf rib6_conf = {
	.ext_sz = sizeof(gr_nh_origin_t),
	.max_nodes = IP6_MAX_ROUTES,
};

static struct rte_rib6 *get_rib6(uint16_t vrf_id) {
	struct rte_rib6 *rib;

	if (vrf_id >= GR_MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	rib = vrf_ribs[vrf_id];
	if (rib == NULL)
		return errno_set_null(ENONET);

	return rib;
}

static struct rte_rib6 *get_or_create_rib6(uint16_t vrf_id) {
	struct rte_rib6 *rib;

	if (vrf_id >= GR_MAX_VRFS)
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

struct nexthop *rib6_lookup_exact(
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

static int rib6_insert_or_replace(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	struct nexthop *nh,
	bool replace
) {
	struct rte_rib6 *rib = get_or_create_rib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	struct nexthop *existing = NULL;
	struct rte_ipv6_addr tmp;
	struct rte_rib6_node *rn;
	gr_nh_origin_t *o;
	int ret;

	nexthop_incref(nh);
	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);

	if (rib == NULL) {
		ret = -errno;
		goto fail;
	}

	if ((rn = rte_rib6_lookup_exact(rib, scoped_ip, prefixlen)) == NULL) {
		rn = rte_rib6_insert(rib, scoped_ip, prefixlen);
		if (rn == NULL) {
			ret = -rte_errno;
			goto fail;
		}
	} else {
		uintptr_t nh_id;
		rte_rib6_get_nh(rn, &nh_id);
		existing = nh_id_to_ptr(nh_id);
		if (!replace) {
			ret = nexthop_equal(nh, existing) ? -EEXIST : -EBUSY;
			goto fail;
		}
	}

	nh->flags |= GR_NH_F_GATEWAY;

	rte_rib6_set_nh(rn, nh_ptr_to_id(nh));
	o = rte_rib6_get_ext(rn);
	gr_nh_origin_t old_origin = origin;
	if (existing)
		old_origin = *o;
	*o = origin;
	fib6_insert(vrf_id, iface_id, scoped_ip, prefixlen, nh);
	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP6_ROUTE_ADD,
			&(struct gr_ip6_route) {
				{*ip, prefixlen},
				nh->base,
				vrf_id,
				origin,
			}
		);
	}

	// Update statistics
	if (vrf_id < GR_MAX_VRFS) {
		if (existing) {
			// Replace case: total unchanged; adjust origin bucket if changed
			if (origin != old_origin) {
				if (stats[vrf_id].by_origin[old_origin] > 0)
					stats[vrf_id].by_origin[old_origin]--;
				stats[vrf_id].by_origin[origin]++;
			}
		} else {
			// New insert
			stats[vrf_id].total_routes++;
			stats[vrf_id].by_origin[origin]++;
		}
	}

	if (existing)
		nexthop_decref(existing);

	return 0;
fail:
	nexthop_decref(nh);
	return errno_set(-ret);
}

int rib6_insert(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	struct nexthop *nh
) {
	return rib6_insert_or_replace(vrf_id, iface_id, ip, prefixlen, origin, nh, false);
}

int rib6_delete(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	gr_nh_type_t nh_type
) {
	struct rte_rib6 *rib = get_rib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	gr_nh_origin_t *o, origin;
	struct rte_ipv6_addr tmp;
	struct rte_rib6_node *rn;
	struct nexthop *nh;
	uintptr_t nh_id;

	if (rib == NULL)
		return -errno;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	rn = rte_rib6_lookup_exact(rib, scoped_ip, prefixlen);
	if (rn == NULL)
		return errno_set(ENOENT);

	o = rte_rib6_get_ext(rn);
	origin = *o;
	rte_rib6_get_nh(rn, &nh_id);
	nh = nh_id_to_ptr(nh_id);
	if (nh->type != nh_type)
		return errno_set(EINVAL);

	rte_rib6_remove(rib, scoped_ip, prefixlen);
	fib6_remove(vrf_id, iface_id, scoped_ip, prefixlen);

	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP6_ROUTE_DEL,
			&(struct gr_ip6_route) {
				{*ip, prefixlen},
				nh->base,
				vrf_id,
				origin,
			}
		);
	}
	// Update statistics
	if (vrf_id < GR_MAX_VRFS) {
		if (stats[vrf_id].total_routes > 0)
			stats[vrf_id].total_routes--;
		if (stats[vrf_id].by_origin[origin] > 0)
			stats[vrf_id].by_origin[origin]--;
	}

	nexthop_decref(nh);

	return 0;
}

static struct api_out route6_add(const void *request, void ** /*response*/) {
	const struct gr_ip6_route_add_req *req = request;
	struct nexthop *nh;
	int ret;

	if (req->origin == GR_NH_ORIGIN_INTERNAL)
		return api_out(EINVAL, 0);

	if (req->nh_id != GR_NH_ID_UNSET) {
		nh = nexthop_lookup_by_id(req->nh_id);
		if (nh == NULL)
			return api_out(ENOENT, 0);
	} else if ((nh = nexthop_lookup(GR_AF_IP6, req->vrf_id, GR_IFACE_ID_UNDEF, &req->nh))
		   == NULL) {
		// ensure route gateway is reachable
		if ((nh = rib6_lookup(req->vrf_id, GR_IFACE_ID_UNDEF, &req->nh)) == NULL)
			return api_out(EHOSTUNREACH, 0);

		// if the route gateway is reachable via a prefix route,
		// create a new unresolved nexthop
		if (!rte_ipv6_addr_eq(&nh->ipv6, &req->nh)) {
			nh = nexthop_new(&(struct gr_nexthop) {
				.type = GR_NH_T_L3,
				.af = GR_AF_IP6,
				.vrf_id = nh->vrf_id,
				.iface_id = nh->iface_id,
				.ipv6 = req->nh,
				.origin = req->origin,
			});
			if (nh == NULL)
				return api_out(errno, 0);
		}
	}

	// if route insert fails, the created nexthop will be freed
	ret = rib6_insert_or_replace(
		req->vrf_id,
		nh->iface_id,
		&req->dest.ip,
		req->dest.prefixlen,
		req->origin,
		nh,
		req->exist_ok
	);

	return api_out(-ret, 0);
}

static struct api_out route6_del(const void *request, void ** /*response*/) {
	const struct gr_ip6_route_del_req *req = request;
	struct nexthop *nh = NULL;
	int ret;

	nh = rib6_lookup(req->vrf_id, GR_IFACE_ID_UNDEF, &req->dest.ip);
	ret = rib6_delete(
		req->vrf_id,
		GR_IFACE_ID_UNDEF,
		&req->dest.ip,
		req->dest.prefixlen,
		nh ? nh->type : GR_NH_T_L3
	);
	if (ret == -ENOENT && req->missing_ok)
		ret = 0;

	if (nh && nh->ref_count == 1)
		nh->flags &= ~GR_NH_F_GATEWAY;

	return api_out(-ret, 0);
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
	resp->nh.mac = nh->mac;
	resp->nh.flags = nh->flags;

	*response = resp;

	return api_out(0, sizeof(*resp));
}

void rib6_iter(uint16_t vrf_id, rib6_iter_cb_t cb, void *priv) {
	static const struct rte_ipv6_addr unspec = RTE_IPV6_ADDR_UNSPEC;
	struct rte_rib6_node *rn;
	struct rte_ipv6_addr ip;
	gr_nh_origin_t *origin;
	struct rte_rib6 *rib;
	uint8_t prefixlen;
	uintptr_t nh_id;

	for (uint16_t v = 0; v < GR_MAX_VRFS; v++) {
		rib = vrf_ribs[v];
		if (rib == NULL || (v != vrf_id && vrf_id != UINT16_MAX))
			continue;

		rn = NULL;
		while ((rn = rte_rib6_get_nxt(rib, &unspec, 0, rn, RTE_RIB6_GET_NXT_ALL)) != NULL) {
			rte_rib6_get_ip(rn, &ip);
			rte_rib6_get_depth(rn, &prefixlen);
			origin = rte_rib6_get_ext(rn);
			rte_rib6_get_nh(rn, &nh_id);
			cb(v, &ip, prefixlen, *origin, nh_id_to_ptr(nh_id), priv);
		}
		// check if there is a default route configured
		if ((rn = rte_rib6_lookup_exact(rib, &unspec, 0)) != NULL) {
			rte_rib6_get_ip(rn, &ip);
			rte_rib6_get_depth(rn, &prefixlen);
			origin = rte_rib6_get_ext(rn);
			rte_rib6_get_nh(rn, &nh_id);
			cb(v, &ip, prefixlen, *origin, nh_id_to_ptr(nh_id), priv);
		}
	}
}

static void route6_list_cb(
	uint16_t vrf_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	const struct nexthop *nh,
	void *priv
) {
	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_vec struct gr_ip6_route **routes = priv;
		struct gr_ip6_route r = {
			.vrf_id = vrf_id,
			.dest = {*ip, prefixlen},
			.nh = nh->base,
			.origin = origin,
		};
		gr_vec_add(*routes, r);
	}
}

static struct api_out route6_list(const void *request, void **response) {
	const struct gr_ip6_route_list_req *req = request;
	struct gr_ip6_route_list_resp *resp = NULL;
	gr_vec struct gr_ip6_route *routes = NULL;
	size_t len;

	rib6_iter(req->vrf_id, route6_list_cb, &routes);

	len = sizeof(*resp) + gr_vec_len(routes) * sizeof(struct gr_ip6_route);
	if ((resp = calloc(1, len)) == NULL) {
		gr_vec_free(routes);
		return api_out(ENOMEM, 0);
	}

	resp->n_routes = gr_vec_len(routes);
	memcpy(resp->routes, routes, gr_vec_len(routes) * sizeof(resp->routes[0]));
	gr_vec_free(routes);

	*response = resp;

	return api_out(0, len);
}

static void route6_init(struct event_base *) {
	// Initialize statistics arrays to zero
	memset(stats, 0, sizeof(stats));

	vrf_ribs = rte_calloc(
		__func__, GR_MAX_VRFS, sizeof(struct rte_rib6 *), RTE_CACHE_LINE_SIZE
	);
	if (vrf_ribs == NULL)
		ABORT("rte_calloc(vrf_rib6s): %s", rte_strerror(rte_errno));
}

static void route6_fini(struct event_base *) {
	for (uint16_t vrf_id = 0; vrf_id < GR_MAX_VRFS; vrf_id++) {
		rte_rib6_free(vrf_ribs[vrf_id]);
		vrf_ribs[vrf_id] = NULL;
	}
	rte_free(vrf_ribs);
	vrf_ribs = NULL;
}

static void rib6_cleanup_nh(
	uint16_t vrf_id,
	const struct rte_ipv6_addr *ip,
	uint8_t depth,
	gr_nh_origin_t,
	const struct nexthop *nh,
	void *priv
) {
	const struct nexthop *hop = priv;
	if (nh == hop) {
		LOG(DEBUG, "delete " IP6_F "/%hhu via %u", ip, depth, nh->nh_id);
		rib6_delete(vrf_id, nh->iface_id, ip, depth, nh->type);
	}
}

void rib6_cleanup(struct nexthop *nh) {
	rib6_iter(UINT16_MAX, rib6_cleanup_nh, nh);
}

const struct rib6_stats *rib6_get_stats(uint16_t vrf_id) {
	if (vrf_id >= GR_MAX_VRFS)
		return NULL;
	return &stats[vrf_id];
}

static int
telemetry_rib6_stats_get(const char * /*cmd*/, const char * /*params*/, struct rte_tel_data *d) {
	rte_tel_data_start_dict(d);

	for (uint16_t vrf_id = 0; vrf_id < GR_MAX_VRFS; vrf_id++) {
		const struct rib6_stats *vrf_stats = rib6_get_stats(vrf_id);

		if (vrf_id != 0 && (vrf_stats == NULL || vrf_stats->total_routes == 0))
			continue;

		char vrf_key[32];
		snprintf(vrf_key, sizeof(vrf_key), "%u", vrf_id);

		struct rte_tel_data *vrf_data = rte_tel_data_alloc();
		if (vrf_data == NULL)
			continue;

		rte_tel_data_start_dict(vrf_data);
		rte_tel_data_add_dict_uint(vrf_data, "vrf_id", vrf_id);

		struct rte_tel_data *ipv6_data = rte_tel_data_alloc();
		if (ipv6_data != NULL) {
			rte_tel_data_start_dict(ipv6_data);
			rte_tel_data_add_dict_uint(ipv6_data, "total", vrf_stats->total_routes);
			rte_tel_data_add_dict_uint(
				ipv6_data, "link", vrf_stats->by_origin[GR_NH_ORIGIN_LINK]
			);
			rte_tel_data_add_dict_container(vrf_data, "ipv6", ipv6_data, 1);
		}

		if (rte_tel_data_add_dict_container(d, vrf_key, vrf_data, 0) != 0) {
			rte_tel_data_free(vrf_data);
			continue;
		}
	}

	return 0;
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

static struct gr_event_serializer route6_serializer = {
	.size = sizeof(struct gr_ip6_route),
	.ev_count = 2,
	.ev_types = {GR_EVENT_IP6_ROUTE_ADD, GR_EVENT_IP6_ROUTE_DEL},
};

static struct gr_module route6_module = {
	.name = "ipv6 route",
	.depends_on = "fib6",
	.init = route6_init,
	.fini = route6_fini,
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&route6_add_handler);
	gr_register_api_handler(&route6_del_handler);
	gr_register_api_handler(&route6_get_handler);
	gr_register_api_handler(&route6_list_handler);
	gr_event_register_serializer(&route6_serializer);
	gr_register_module(&route6_module);
	rte_telemetry_register_cmd(
		"/grout/rib6/stats", telemetry_rib6_stats_get, "Get IPv6 RIB statistics"
	);
}
