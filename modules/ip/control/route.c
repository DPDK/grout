// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_ip4.h>
#include <gr_ip4_control.h>
#include <gr_log.h>
#include <gr_metrics.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_queue.h>
#include <gr_rcu.h>
#include <gr_string.h>
#include <gr_vec.h>
#include <gr_vrf.h>

#include <event2/event.h>
#include <rte_build_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_fib.h>
#include <rte_rib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static uint32_t route_counts[GR_MAX_IFACES][UINT_NUM_VALUES(gr_nh_origin_t)];

static uint32_t max_routes_default = 1 << 16;

// Derive num_tbl8 from max_routes for IPv4 DIR24_8.
// Only prefixes longer than /24 consume tbl8 groups. In real-world BGP
// tables, less than 0.1% of prefixes are longer than /24. A ratio of
// 1/500 with a minimum of 256 provides ample headroom.
static inline uint32_t fib4_auto_tbl8(uint32_t max_routes) {
	uint32_t n = max_routes / 500;
	return n < 256 ? 256 : n;
}

static inline uint32_t fib4_get_max_routes(const struct iface *vrf) {
	return iface_info_vrf(vrf)->ipv4.max_routes;
}

static inline uint32_t fib4_get_num_tbl8(const struct iface *vrf) {
	return iface_info_vrf(vrf)->ipv4.num_tbl8;
}

static struct rte_fib *get_fib(uint16_t vrf_id) {
	struct iface *iface = get_vrf_iface(vrf_id);
	if (iface == NULL)
		return NULL;

	struct rte_fib *fib = iface_info_vrf(iface)->fib4;
	if (fib == NULL)
		return errno_set_null(ENONET);

	return fib;
}

static struct rte_fib *create_fib(const struct iface *vrf) {
	struct rte_fib_conf conf = {
		.type = RTE_FIB_DIR24_8,
		.default_nh = 0,
		.max_routes = fib4_get_max_routes(vrf),
		.rib_ext_sz = sizeof(gr_nh_origin_t),
		.dir24_8 = {
			.nh_sz = RTE_FIB_DIR24_8_8B,
			.num_tbl8 = fib4_get_num_tbl8(vrf),
		},
	};
	struct rte_fib *fib;
	static unsigned seq;
	char name[16];
	int ret;

	snprintf(name, sizeof(name), "fib4_%x-%x", vrf->id, seq++);
	fib = rte_fib_create(name, SOCKET_ID_ANY, &conf);
	if (fib == NULL)
		return errno_set_null(rte_errno);

	struct rte_fib_rcu_config rcu_config = {
		.v = gr_datapath_rcu(), .mode = RTE_FIB_QSBR_MODE_DQ
	};
	ret = rte_fib_rcu_qsbr_add(fib, &rcu_config);
	if (ret < 0) {
		rte_fib_free(fib);
		return errno_set_null(-ret);
	}

	return fib;
}

static int fib4_init(struct iface *vrf) {
	struct gr_iface_info_vrf_fib *conf = &iface_info_vrf(vrf)->ipv4;
	struct rte_fib *fib;

	if (!conf->max_routes)
		conf->max_routes = max_routes_default;
	if (!conf->num_tbl8)
		conf->num_tbl8 = fib4_auto_tbl8(conf->max_routes);

	LOG(INFO,
	    "creating IPv4 FIB for VRF %s(%u) max_routes=%u num_tbl8=%u",
	    vrf->name,
	    vrf->id,
	    conf->max_routes,
	    conf->num_tbl8);

	fib = create_fib(vrf);
	if (fib == NULL)
		return errno_log(errno, "create_fib");

	iface_info_vrf(vrf)->fib4 = fib;
	return 0;
}

static inline uintptr_t nh_ptr_to_id(const struct nexthop *nh) {
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

const struct nexthop *fib4_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	uint32_t host_order_ip = rte_be_to_cpu_32(ip);
	struct rte_fib *fib = get_fib(vrf_id);
	uintptr_t nh_id;

	if (fib == NULL)
		return NULL;

	rte_fib_lookup_bulk(fib, &host_order_ip, &nh_id, 1);
	if (nh_id == 0)
		return errno_set_null(EHOSTUNREACH);

	return nh_id_to_ptr(nh_id);
}

struct nexthop *rib4_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	struct rte_fib *fib = get_fib(vrf_id);
	struct rte_rib_node *rn;
	struct rte_rib *rib;
	uintptr_t nh_id;

	if (fib == NULL)
		return NULL;

	rib = rte_fib_get_rib(fib);
	rn = rte_rib_lookup(rib, rte_be_to_cpu_32(ip));
	if (rn == NULL)
		return errno_set_null(ENETUNREACH);

	rte_rib_get_nh(rn, &nh_id);
	return nh_id_to_ptr(nh_id);
}

struct nexthop *rib4_lookup_exact(uint16_t vrf_id, ip4_addr_t ip, uint8_t prefixlen) {
	struct rte_fib *fib = get_fib(vrf_id);
	struct rte_rib_node *rn;
	struct rte_rib *rib;
	uintptr_t nh_id;

	if (fib == NULL)
		return NULL;

	rib = rte_fib_get_rib(fib);
	rn = rte_rib_lookup_exact(rib, rte_be_to_cpu_32(ip), prefixlen);
	if (rn == NULL)
		return errno_set_null(ENETUNREACH);

	rte_rib_get_nh(rn, &nh_id);
	return nh_id_to_ptr(nh_id);
}

struct route4_event {
	struct ip4_net dest;
	uint16_t vrf_id;
	gr_nh_origin_t origin;
	const struct nexthop *nh;
};

static int rib4_insert_or_replace(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	struct nexthop *nh,
	bool replace
) {
	struct rte_fib *fib = get_fib(vrf_id);
	struct nexthop *existing = NULL;
	struct rte_rib_node *rn;
	struct rte_rib *rib;
	gr_nh_origin_t *o;
	int ret;

	if (fib == NULL)
		return -errno;

	if (!nexthop_origin_valid(origin))
		return errno_set(EPFNOSUPPORT);

	rib = rte_fib_get_rib(fib);

	if ((rn = rte_rib_lookup_exact(rib, rte_be_to_cpu_32(ip), prefixlen)) != NULL) {
		uintptr_t nh_id;
		rte_rib_get_nh(rn, &nh_id);
		existing = nh_id_to_ptr(nh_id);
		if (!replace)
			return errno_set(nexthop_equal(nh, existing) ? EEXIST : EBUSY);
	}

	if ((ret = rte_fib_add(fib, rte_be_to_cpu_32(ip), prefixlen, nh_ptr_to_id(nh))) < 0)
		return errno_set(-ret);

	rn = rte_rib_lookup_exact(rib, rte_be_to_cpu_32(ip), prefixlen);
	o = rte_rib_get_ext(rn);
	if (existing) {
		assert(route_counts[vrf_id][*o] > 0);
		route_counts[vrf_id][*o]--;
	}
	*o = origin;
	route_counts[vrf_id][origin]++;

	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP_ROUTE_ADD,
			&(const struct route4_event) {
				.dest = {ip, prefixlen},
				.vrf_id = vrf_id,
				.origin = origin,
				.nh = nh,
			}
		);
	}

	nexthop_incref(nh);
	if (existing)
		nexthop_decref(existing);

	return 0;
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
	struct rte_fib *fib = get_fib(vrf_id);
	gr_nh_origin_t *o, origin;
	struct rte_rib_node *rn;
	struct nexthop *nh;
	struct rte_rib *rib;
	uintptr_t nh_id;
	int ret;

	if (fib == NULL)
		return -errno;

	rib = rte_fib_get_rib(fib);
	rn = rte_rib_lookup_exact(rib, rte_be_to_cpu_32(ip), prefixlen);
	if (rn == NULL)
		return errno_set(ENOENT);

	o = rte_rib_get_ext(rn);
	origin = *o;
	rte_rib_get_nh(rn, &nh_id);
	nh = nh_id_to_ptr(nh_id);
	if (nh->type != nh_type)
		return errno_set(EINVAL);

	if ((ret = rte_fib_delete(fib, rte_be_to_cpu_32(ip), prefixlen)) < 0)
		return errno_set(-ret);

	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP_ROUTE_DEL,
			&(const struct route4_event) {
				.dest = {ip, prefixlen},
				.vrf_id = vrf_id,
				.origin = origin,
				.nh = nh,
			}
		);
	}

	assert(route_counts[vrf_id][origin] > 0);
	route_counts[vrf_id][origin]--;

	nexthop_decref(nh);

	return 0;
}

static struct api_out route4_add(const void *request, struct api_ctx *) {
	const struct gr_ip4_route_add_req *req = request;
	bool created = false;
	struct nexthop *nh;
	int ret;

	if (req->origin == GR_NH_ORIGIN_INTERNAL)
		return api_out(EINVAL, 0, NULL);

	if (req->nh_id != GR_NH_ID_UNSET) {
		nh = nexthop_lookup_id(req->nh_id);
		if (nh == NULL)
			return api_out(ENOENT, 0, NULL);
	} else if ((nh = nexthop_lookup_l3(GR_AF_IP4, req->vrf_id, GR_IFACE_ID_UNDEF, &req->nh))
		   == NULL) {
		// ensure route gateway is reachable
		if ((nh = rib4_lookup(req->vrf_id, req->nh)) == NULL)
			return api_out(EHOSTUNREACH, 0, NULL);

		// if the route gateway is reachable via a prefix route,
		// create a new unresolved nexthop
		if (nh->type != GR_NH_T_L3 || nexthop_info_l3(nh)->ipv4 != req->nh) {
			nh = nexthop_new(
				&(struct gr_nexthop_base) {
					.type = GR_NH_T_L3,
					.iface_id = nh->iface_id,
					.vrf_id = req->vrf_id,
					.origin = req->origin,
				},
				&(struct gr_nexthop_info_l3) {
					.af = GR_AF_IP4,
					.ipv4 = req->nh,
				}
			);
			if (nh == NULL)
				return api_out(errno, 0, NULL);
			created = true;
		}
	}

	// if route insert fails, the created nexthop will be freed
	ret = rib4_insert_or_replace(
		req->vrf_id, req->dest.ip, req->dest.prefixlen, req->origin, nh, req->exist_ok
	);
	if (ret < 0 && created)
		nexthop_decref(nh);

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

	return api_out(-ret, 0, NULL);
}

static struct api_out route4_get(const void *request, struct api_ctx *) {
	const struct gr_ip4_route_get_req *req = request;
	const struct nexthop *nh = NULL;
	struct gr_nexthop *pub = NULL;
	size_t len;

	nh = rib4_lookup(req->vrf_id, req->dest);
	if (nh == NULL)
		return api_out(ENETUNREACH, 0, NULL);

	pub = nexthop_to_api(nh, &len);
	if (pub == NULL)
		return api_out(errno, 0, NULL);

	return api_out(0, len, pub);
}

static void rib4_iter_one(struct rte_rib *rib, uint16_t vrf_id, rib4_iter_cb_t cb, void *priv) {
	struct rte_rib_node *rn;
	gr_nh_origin_t *origin;
	uint8_t prefixlen;
	uintptr_t nh_id;
	uint32_t ip;

	rn = NULL;
	while ((rn = rte_rib_get_nxt(rib, 0, 0, rn, RTE_RIB_GET_NXT_ALL)) != NULL) {
		rte_rib_get_ip(rn, &ip);
		rte_rib_get_depth(rn, &prefixlen);
		origin = rte_rib_get_ext(rn);
		rte_rib_get_nh(rn, &nh_id);
		cb(vrf_id, rte_cpu_to_be_32(ip), prefixlen, *origin, nh_id_to_ptr(nh_id), priv);
	}

	// check if there is a default route configured
	if ((rn = rte_rib_lookup_exact(rib, 0, 0)) != NULL) {
		rte_rib_get_ip(rn, &ip);
		rte_rib_get_depth(rn, &prefixlen);
		origin = rte_rib_get_ext(rn);
		rte_rib_get_nh(rn, &nh_id);
		cb(vrf_id, rte_cpu_to_be_32(ip), prefixlen, *origin, nh_id_to_ptr(nh_id), priv);
	}
}

void rib4_iter(uint16_t vrf_id, rib4_iter_cb_t cb, void *priv) {
	for (uint16_t v = 0; v < GR_MAX_IFACES; v++) {
		if (v != vrf_id && vrf_id != GR_VRF_ID_UNDEF)
			continue;
		struct iface *iface = get_vrf_iface(v);
		if (iface == NULL)
			continue;
		struct rte_fib *fib = iface_info_vrf(iface)->fib4;
		if (fib == NULL)
			continue;
		rib4_iter_one(rte_fib_get_rib(fib), v, cb, priv);
	}
}

struct route4_iterator {
	struct api_ctx *ctx;
	int ret;
};

static void route4_list_cb(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	const struct nexthop *nh,
	void *priv
) {
	struct route4_iterator *iter = priv;
	if (origin != GR_NH_ORIGIN_INTERNAL && iter->ret == 0) {
		struct gr_ip4_route *r;
		struct gr_nexthop *pub;
		size_t nh_len, len;

		pub = nexthop_to_api(nh, &nh_len);
		if (pub == NULL) {
			iter->ret = errno;
			LOG(ERR, "nexthop_export: %s", strerror(errno));
			return;
		}

		len = sizeof(*r) - sizeof(r->nh) + nh_len;
		r = malloc(len);
		if (r != NULL) {
			r->vrf_id = vrf_id;
			r->dest.ip = ip;
			r->dest.prefixlen = prefixlen;
			r->origin = origin;
			memcpy(&r->nh, pub, nh_len);
			api_send(iter->ctx, len, r);
		} else {
			LOG(ERR, "cannot allocate memory");
			iter->ret = ENOMEM;
		}
		free(pub);
		free(r);
	}
}

static struct api_out route4_list(const void *request, struct api_ctx *ctx) {
	const struct gr_ip4_route_list_req *req = request;
	struct route4_iterator iter = {.ctx = ctx, .ret = 0};

	rib4_iter(req->vrf_id, route4_list_cb, &iter);

	return api_out(iter.ret, 0, NULL);
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
	rib4_iter(GR_VRF_ID_UNDEF, rib4_cleanup_nh, nh);
}

METRIC_GAUGE(m_routes, "rib4_routes", "Number of IPv4 routes by origin.");
METRIC_GAUGE(m_max_routes, "rib4_max_routes", "Maximum number of IPv4 routes.");
#ifdef HAVE_RTE_FIB_TBL8_GET_STATS
METRIC_GAUGE(m_max_tbl8, "fib4_max_tbl8", "Maximum number of IPv4 FIB tbl8 groups.");
METRIC_GAUGE(m_used_tbl8, "fib4_used_tbl8", "Used IPv4 FIB tbl8 groups.");
#endif

static void rib4_metrics_collect(struct gr_metrics_writer *w) {
	struct gr_metrics_ctx ctx;
	char vrf[16];

	for (uint16_t vrf_id = 0; vrf_id < GR_MAX_IFACES; vrf_id++) {
		const struct iface *vrf_iface = get_vrf_iface(vrf_id);
		if (vrf_iface == NULL)
			continue;

		snprintf(vrf, sizeof(vrf), "%u", vrf_id);

		for (unsigned o = 0; o < UINT_NUM_VALUES(gr_nh_origin_t); o++) {
			if (!nexthop_origin_valid(o))
				continue;
			gr_metrics_ctx_init(
				&ctx, w, "vrf", vrf, "origin", gr_nh_origin_name(o), NULL
			);
			gr_metric_emit(&ctx, &m_routes, route_counts[vrf_id][o]);
		}

		gr_metrics_ctx_init(&ctx, w, "vrf", vrf, NULL);
		gr_metric_emit(&ctx, &m_max_routes, fib4_get_max_routes(vrf_iface));
#ifdef HAVE_RTE_FIB_TBL8_GET_STATS
		uint32_t used_tbl8, total_tbl8;
		struct rte_fib *fib = iface_info_vrf(vrf_iface)->fib4;
		if (fib != NULL) {
			rte_fib_tbl8_get_stats(fib, &used_tbl8, &total_tbl8);
			gr_metric_emit(&ctx, &m_max_tbl8, total_tbl8);
			gr_metric_emit(&ctx, &m_used_tbl8, used_tbl8);
		}
#endif
	}
}

static struct gr_metrics_collector rib4_collector = {
	.name = "rib4",
	.collect = rib4_metrics_collect,
};

static int serialize_route4_event(const void *obj, void **buf) {
	const struct route4_event *priv = obj;
	struct gr_ip4_route *r;
	struct gr_nexthop *nh;
	size_t nh_len;
	int len;

	nh = nexthop_to_api(priv->nh, &nh_len);
	if (nh == NULL)
		return -errno;

	len = sizeof(*r) - sizeof(r->nh) + nh_len;

	r = malloc(len);
	if (r == NULL) {
		len = -errno;
	} else {
		r->vrf_id = priv->vrf_id;
		r->dest = priv->dest;
		r->origin = priv->origin;
		memcpy(&r->nh, nh, nh_len);
		*buf = r;
	}
	free(nh);

	return len;
}

struct fib4_migrate_ctx {
	struct rte_fib *new_fib;
	uint32_t counts[UINT_NUM_VALUES(gr_nh_origin_t)];
};

static void fib4_migrate_cb(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	const struct nexthop *nh,
	void *priv
) {
	uint32_t host_ip = rte_be_to_cpu_32(ip);
	struct fib4_migrate_ctx *ctx = priv;
	int ret;

	ret = rte_fib_add(ctx->new_fib, host_ip, prefixlen, nh_ptr_to_id(nh));
	if (ret < 0) {
		if (nh->type == GR_NH_T_L3 && (nexthop_info_l3(nh)->flags & NH_LOCAL_ADDR_FLAGS)) {
			const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
			LOG(WARNING,
			    "iface %u: dropping local address " IP4_F "/%hhu: %s",
			    nh->iface_id,
			    &l3->ipv4,
			    l3->prefixlen,
			    rte_strerror(-ret));
			addr4_delete(nh->iface_id, l3->ipv4, l3->prefixlen);
		} else {
			LOG(WARNING,
			    "vrf %u: dropping route " IP4_F "/%hhu: %s",
			    vrf_id,
			    &ip,
			    prefixlen,
			    rte_strerror(-ret));
			if (origin != GR_NH_ORIGIN_INTERNAL) {
				gr_event_push(
					GR_EVENT_IP_ROUTE_DEL,
					&(const struct route4_event) {
						.dest = {ip, prefixlen},
						.vrf_id = vrf_id,
						.origin = origin,
						.nh = nh,
					}
				);
			}
			nexthop_decref((void *)nh);
		}
		return;
	}

	struct rte_rib *rib = rte_fib_get_rib(ctx->new_fib);
	struct rte_rib_node *rn = rte_rib_lookup_exact(rib, host_ip, prefixlen);
	gr_nh_origin_t *o = rte_rib_get_ext(rn);
	*o = origin;
	ctx->counts[origin]++;
}

static uint32_t fib4_total_routes(uint16_t vrf_id) {
	uint32_t total = 0;
	for (unsigned o = 0; o < UINT_NUM_VALUES(gr_nh_origin_t); o++)
		total += route_counts[vrf_id][o];
	return total;
}

static int fib4_reconfig(struct iface *vrf) {
	struct gr_iface_info_vrf_fib *conf = &iface_info_vrf(vrf)->ipv4;
	struct rte_fib *old_fib, *new_fib;

	if (!conf->max_routes)
		conf->max_routes = max_routes_default;
	if (!conf->num_tbl8)
		conf->num_tbl8 = fib4_auto_tbl8(conf->max_routes);

	old_fib = iface_info_vrf(vrf)->fib4;
	new_fib = create_fib(vrf);
	if (new_fib == NULL)
		return errno_log(errno, "create_fib");

	struct fib4_migrate_ctx ctx = {.new_fib = new_fib};
	rib4_iter_one(rte_fib_get_rib(old_fib), vrf->id, fib4_migrate_cb, &ctx);

	iface_info_vrf(vrf)->fib4 = new_fib;
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
	rte_fib_free(old_fib);

	memcpy(route_counts[vrf->id], ctx.counts, sizeof(ctx.counts));

	return 0;
}

static struct api_out fib4_info_list(const void *request, struct api_ctx *ctx) {
	const struct gr_ip4_fib_info_list_req *req = request;
	struct gr_fib4_info info;

	info.vrf_id = GR_VRF_ID_UNDEF;
	info.max_routes = max_routes_default;
	info.used_routes = 0;
	info.num_tbl8 = fib4_auto_tbl8(max_routes_default);
	info.used_tbl8 = 0;
	api_send(ctx, sizeof(info), &info);

	for (uint16_t v = 0; v < GR_MAX_IFACES; v++) {
		if (v != req->vrf_id && req->vrf_id != GR_VRF_ID_UNDEF)
			continue;
		const struct iface *vrf = get_vrf_iface(v);
		if (vrf == NULL)
			continue;
		info.vrf_id = v;
		info.max_routes = fib4_get_max_routes(vrf);
		info.used_routes = fib4_total_routes(v);
#ifdef HAVE_RTE_FIB_TBL8_GET_STATS
		struct rte_fib *fib = iface_info_vrf(vrf)->fib4;
		if (fib != NULL)
			rte_fib_tbl8_get_stats(fib, &info.used_tbl8, &info.num_tbl8);
#else
		info.num_tbl8 = fib4_get_num_tbl8(vrf);
		info.used_tbl8 = 0;
#endif
		api_send(ctx, sizeof(info), &info);
	}

	return api_out(0, 0, NULL);
}

static struct gr_module route4_module = {
	.name = "ip_route",
	.depends_on = "nexthop",
};

static void route4_vrf_rm(
	uint16_t vrf_id,
	ip4_addr_t ip,
	uint8_t depth,
	gr_nh_origin_t origin,
	const struct nexthop *nh,
	void *priv
) {
	const struct iface *vrf = priv;

	LOG(DEBUG, "VRF %s(%u): " IP4_F "/%hhu", vrf->name, vrf->id, &ip, depth);

	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP_ROUTE_DEL,
			&(const struct route4_event) {
				.dest = {ip, depth},
				.vrf_id = vrf_id,
				.origin = origin,
				.nh = nh,
			}
		);
	}
	nexthop_decref((void *)nh);
}

static void fib4_fini(struct iface *vrf) {
	struct rte_fib *fib = iface_info_vrf(vrf)->fib4;

	iface_info_vrf(vrf)->fib4 = NULL;
	if (fib != NULL) {
		LOG(INFO, "destroying IPv4 FIB for VRF %s(%u)", vrf->name, vrf->id);
		rib4_iter_one(rte_fib_get_rib(fib), vrf->id, route4_vrf_rm, (void *)vrf);
		rte_fib_free(fib);
	}
	memset(route_counts[vrf->id], 0, sizeof(route_counts[vrf->id]));
}

static struct api_out fib4_default_set(const void *request, struct api_ctx *) {
	const struct gr_ip4_fib_default_set_req *req = request;

	if (req->max_routes == 0)
		return api_out(EINVAL, 0, NULL);

	if (req->max_routes != max_routes_default) {
		LOG(INFO, "IPv4 default max_routes %u -> %u", max_routes_default, req->max_routes);
		max_routes_default = req->max_routes;
	}

	return api_out(0, 0, NULL);
}

static const struct vrf_fib_ops fib4_ops = {
	.init = fib4_init,
	.reconfig = fib4_reconfig,
	.fini = fib4_fini,
};

RTE_INIT(control_ip_init) {
	gr_api_handler(GR_IP4_ROUTE_ADD, route4_add);
	gr_api_handler(GR_IP4_ROUTE_DEL, route4_del);
	gr_api_handler(GR_IP4_ROUTE_GET, route4_get);
	gr_api_handler(GR_IP4_ROUTE_LIST, route4_list);
	gr_api_handler(GR_IP4_FIB_DEFAULT_SET, fib4_default_set);
	gr_api_handler(GR_IP4_FIB_INFO_LIST, fib4_info_list);
	gr_event_serializer(GR_EVENT_IP_ROUTE_ADD, serialize_route4_event, 0);
	gr_event_serializer(GR_EVENT_IP_ROUTE_DEL, serialize_route4_event, 0);
	gr_register_module(&route4_module);
	gr_metrics_register(&rib4_collector);
	vrf_fib_ops_register(GR_AF_IP4, &fib4_ops);
}
