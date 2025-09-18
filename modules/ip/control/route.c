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
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_rib.h>
#include <rte_telemetry.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_rib **vrf_ribs;
static struct rib4_stats stats[GR_MAX_VRFS];

static struct rte_rib_conf rib_conf = {
	.ext_sz = sizeof(gr_nh_origin_t),
	.max_nodes = IP4_MAX_ROUTES,
};

static struct rte_rib *get_rib(uint16_t vrf_id) {
	struct rte_rib *rib;

	if (vrf_id >= GR_MAX_VRFS)
		return errno_set_null(EOVERFLOW);

	rib = vrf_ribs[vrf_id];
	if (rib == NULL)
		return errno_set_null(ENONET);

	return rib;
}

static struct rte_rib *get_or_create_rib(uint16_t vrf_id) {
	struct rte_rib *rib;

	if (vrf_id >= GR_MAX_VRFS)
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

static int rib4_insert_or_replace(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	struct nexthop *nh,
	bool replace
) {
	struct rte_rib *rib = get_or_create_rib(vrf_id);
	struct nexthop *existing = NULL;
	struct rte_rib_node *rn;
	gr_nh_origin_t *o;
	int ret;

	nexthop_incref(nh);

	if (rib == NULL) {
		ret = -errno;
		goto fail;
	}

	if ((rn = rte_rib_lookup_exact(rib, rte_be_to_cpu_32(ip), prefixlen)) == NULL) {
		rn = rte_rib_insert(rib, rte_be_to_cpu_32(ip), prefixlen);
		if (rn == NULL) {
			ret = -rte_errno;
			goto fail;
		}
	} else {
		uintptr_t nh_id;
		rte_rib_get_nh(rn, &nh_id);
		existing = nh_id_to_ptr(nh_id);
		if (!replace) {
			ret = nexthop_equal(nh, existing) ? -EEXIST : -EBUSY;
			goto fail;
		}
	}

	nh->flags |= GR_NH_F_GATEWAY;

	rte_rib_set_nh(rn, nh_ptr_to_id(nh));
	o = rte_rib_get_ext(rn);
	gr_nh_origin_t old_origin = origin;
	if (existing)
		old_origin = *o;
	*o = origin;
	fib4_insert(vrf_id, ip, prefixlen, nh);
	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP_ROUTE_ADD,
			&(struct gr_ip4_route) {
				{ip, prefixlen},
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

int rib4_insert(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	struct nexthop *nh
) {
	return rib4_insert_or_replace(vrf_id, ip, prefixlen, origin, nh, false);
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

static struct api_out route4_add(const void *request, struct api_ctx *) {
	const struct gr_ip4_route_add_req *req = request;
	struct nexthop *nh;
	int ret;

	if (req->origin == GR_NH_ORIGIN_INTERNAL)
		return api_out(EINVAL, 0, NULL);

	if (req->nh_id != GR_NH_ID_UNSET) {
		nh = nexthop_lookup_by_id(req->nh_id);
		if (nh == NULL)
			return api_out(ENOENT, 0, NULL);
	} else if ((nh = nexthop_lookup(GR_AF_IP4, req->vrf_id, GR_IFACE_ID_UNDEF, &req->nh))
		   == NULL) {
		// ensure route gateway is reachable
		if ((nh = rib4_lookup(req->vrf_id, req->nh)) == NULL)
			return api_out(EHOSTUNREACH, 0, NULL);

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
				return api_out(errno, 0, NULL);
		}
	}

	// if route insert fails, the created nexthop will be freed
	ret = rib4_insert_or_replace(
		req->vrf_id, req->dest.ip, req->dest.prefixlen, req->origin, nh, req->exist_ok
	);

	return api_out(-ret, 0, NULL);
}

static struct api_out route4_del(const void *request, struct api_ctx *) {
	const struct gr_ip4_route_del_req *req = request;
	struct nexthop *nh = NULL;
	int ret;

	nh = rib4_lookup(req->vrf_id, req->dest.ip);
	ret = rib4_delete(
		req->vrf_id, req->dest.ip, req->dest.prefixlen, nh ? nh->type : GR_NH_T_L3
	);
	if (ret == -ENOENT && req->missing_ok)
		ret = 0;

	if (nh && nh->ref_count == 1)
		nh->flags &= ~GR_NH_F_GATEWAY;

	return api_out(-ret, 0, NULL);
}

static struct api_out route4_get(const void *request, struct api_ctx *) {
	const struct gr_ip4_route_get_req *req = request;
	struct gr_ip4_route_get_resp *resp = NULL;
	const struct nexthop *nh = NULL;

	nh = rib4_lookup(req->vrf_id, req->dest);
	if (nh == NULL)
		return api_out(ENETUNREACH, 0, NULL);

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->nh = nh->base;

	return api_out(0, sizeof(*resp), resp);
}

void rib4_iter(uint16_t vrf_id, rib4_iter_cb_t cb, void *priv) {
	struct rte_rib_node *rn;
	gr_nh_origin_t *origin;
	struct rte_rib *rib;
	uint8_t prefixlen;
	uintptr_t nh_id;
	uint32_t ip;

	for (uint16_t v = 0; v < GR_MAX_VRFS; v++) {
		rib = vrf_ribs[v];
		if (rib == NULL || (v != vrf_id && vrf_id != UINT16_MAX))
			continue;

		rn = NULL;
		while ((rn = rte_rib_get_nxt(rib, 0, 0, rn, RTE_RIB_GET_NXT_ALL)) != NULL) {
			rte_rib_get_ip(rn, &ip);
			rte_rib_get_depth(rn, &prefixlen);
			origin = rte_rib_get_ext(rn);
			rte_rib_get_nh(rn, &nh_id);
			cb(v, rte_cpu_to_be_32(ip), prefixlen, *origin, nh_id_to_ptr(nh_id), priv);
		}
		// check if there is a default route configured
		if ((rn = rte_rib_lookup_exact(rib, 0, 0)) != NULL) {
			rte_rib_get_ip(rn, &ip);
			rte_rib_get_depth(rn, &prefixlen);
			origin = rte_rib_get_ext(rn);
			rte_rib_get_nh(rn, &nh_id);
			cb(v, rte_cpu_to_be_32(ip), prefixlen, *origin, nh_id_to_ptr(nh_id), priv);
		}
	}
}

static void route4_list_cb(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	const struct nexthop *nh,
	void *priv
) {
	if (origin != GR_NH_ORIGIN_INTERNAL) {
		struct api_ctx *ctx = priv;
		struct gr_ip4_route r = {
			.vrf_id = vrf_id,
			.dest = {ip, prefixlen},
			.nh = nh->base,
			.origin = origin,
		};
		api_send(ctx, sizeof(r), &r);
	}
}

static struct api_out route4_list(const void *request, struct api_ctx *ctx) {
	const struct gr_ip4_route_list_req *req = request;

	rib4_iter(req->vrf_id, route4_list_cb, (void *)ctx);

	return api_out(0, 0, NULL);
}

static void route4_init(struct event_base *) {
	memset(stats, 0, sizeof(stats));
	vrf_ribs = rte_calloc(__func__, GR_MAX_VRFS, sizeof(struct rte_rib *), RTE_CACHE_LINE_SIZE);
	if (vrf_ribs == NULL)
		ABORT("rte_calloc(vrf_ribs): %s", rte_strerror(rte_errno));
}

static void route4_fini(struct event_base *) {
	for (uint16_t vrf_id = 0; vrf_id < GR_MAX_VRFS; vrf_id++) {
		rte_rib_free(vrf_ribs[vrf_id]);
		vrf_ribs[vrf_id] = NULL;
	}
	rte_free(vrf_ribs);
	vrf_ribs = NULL;
}

static void rib4_cleanup_nh(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t depth,
	gr_nh_origin_t,
	const struct nexthop *nh,
	void *priv
) {
	const struct nexthop *hop = priv;
	if (nh == hop) {
		LOG(DEBUG, "delete " IP4_F "/%hhu via %u", &ip, depth, nh->nh_id);
		rib4_delete(vrf_id, ip, depth, nh->type);
	}
}

void rib4_cleanup(struct nexthop *nh) {
	rib4_iter(UINT16_MAX, rib4_cleanup_nh, nh);
}

const struct rib4_stats *rib4_get_stats(uint16_t vrf_id) {
	if (vrf_id >= GR_MAX_VRFS)
		return NULL;
	return &stats[vrf_id];
}

static int
telemetry_rib4_stats_get(const char * /*cmd*/, const char * /*params*/, struct rte_tel_data *d) {
	rte_tel_data_start_dict(d);

	for (uint16_t vrf_id = 0; vrf_id < GR_MAX_VRFS; vrf_id++) {
		const struct rib4_stats *vrf_stats = rib4_get_stats(vrf_id);

		if (vrf_id != 0 && (vrf_stats == NULL || vrf_stats->total_routes == 0))
			continue;

		char vrf_key[32];
		snprintf(vrf_key, sizeof(vrf_key), "%u", vrf_id);

		struct rte_tel_data *vrf_data = rte_tel_data_alloc();
		if (vrf_data == NULL)
			continue;

		rte_tel_data_start_dict(vrf_data);
		rte_tel_data_add_dict_uint(vrf_data, "vrf_id", vrf_id);

		struct rte_tel_data *ipv4_data = rte_tel_data_alloc();
		if (ipv4_data != NULL) {
			rte_tel_data_start_dict(ipv4_data);
			rte_tel_data_add_dict_uint(ipv4_data, "total", vrf_stats->total_routes);
			rte_tel_data_add_dict_uint(
				ipv4_data, "link", vrf_stats->by_origin[GR_NH_ORIGIN_LINK]
			);
			rte_tel_data_add_dict_container(vrf_data, "ipv4", ipv4_data, 1);
		}

		if (rte_tel_data_add_dict_container(d, vrf_key, vrf_data, 0) != 0) {
			rte_tel_data_free(vrf_data);
			continue;
		}
	}

	return 0;
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
	rte_telemetry_register_cmd(
		"/grout/rib4/stats", telemetry_rib4_stats_get, "Get IPv4 RIB statistics"
	);
}
