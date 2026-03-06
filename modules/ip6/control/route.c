// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_ip6.h>
#include <gr_ip6_control.h>
#include <gr_log.h>
#include <gr_metrics.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_queue.h>
#include <gr_rcu.h>
#include <gr_string.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_build_config.h>
#include <rte_errno.h>
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

static uint32_t route_counts[GR_MAX_IFACES][UINT_NUM_VALUES(gr_nh_origin_t)];

static struct {
	uint32_t max_routes; // 0 = default
	uint32_t num_tbl8; // 0 = auto
} fib6_conf[GR_MAX_IFACES];

static uint32_t max_routes_default = 1 << 16;

static inline uint32_t fib6_get_max_routes(uint16_t vrf_id) {
	return fib6_conf[vrf_id].max_routes ?: max_routes_default;
}

// Derive num_tbl8 from max_routes for IPv6 TRIE.
// The trie uses 8-bit levels beyond the first 24 bits. IPv6 routes at
// /48 consume up to 3 tbl8 groups each. Sharing reduces actual usage
// but a ratio of 4x is needed to handle real-world prefix distributions
// without exhaustion.
static inline uint32_t fib6_auto_tbl8(uint32_t max_routes) {
	uint32_t n = max_routes * 4;
	return n < 256 ? 256 : n;
}

static inline uint32_t fib6_get_num_tbl8(uint16_t vrf_id) {
	return fib6_conf[vrf_id].num_tbl8 ?: fib6_auto_tbl8(fib6_get_max_routes(vrf_id));
}

static struct rte_fib6 *get_fib6(uint16_t vrf_id) {
	struct rte_fib6 *fib;

	if (vrf_id >= GR_MAX_IFACES)
		return errno_set_null(EOVERFLOW);

	fib = vrf_fibs[vrf_id];
	if (fib == NULL)
		return errno_set_null(ENONET);

	return fib;
}

static struct rte_fib6 *create_fib6(uint16_t vrf_id) {
	struct rte_fib6_conf conf = {
		.type = RTE_FIB6_TRIE,
		.default_nh = 0,
		.max_routes = fib6_get_max_routes(vrf_id),
		.rib_ext_sz = sizeof(gr_nh_origin_t),
		.trie = {
			.nh_sz = RTE_FIB6_TRIE_8B,
			.num_tbl8 = fib6_get_num_tbl8(vrf_id),
		},
	};
	struct rte_fib6 *fib;
	static unsigned seq;
	char name[16];
	int ret;

	snprintf(name, sizeof(name), "fib6_%x-%x", vrf_id, seq++);
	fib = rte_fib6_create(name, SOCKET_ID_ANY, &conf);
	if (fib == NULL)
		return errno_set_null(rte_errno);

	struct rte_fib6_rcu_config rcu_config = {
		.v = gr_datapath_rcu(), .mode = RTE_FIB6_QSBR_MODE_DQ
	};
	ret = rte_fib6_rcu_qsbr_add(fib, &rcu_config);
	if (ret < 0) {
		rte_fib6_free(fib);
		return errno_set_null(-ret);
	}

	return fib;
}

static struct rte_fib6 *get_or_create_fib6(uint16_t vrf_id) {
	const struct iface *iface = get_vrf_iface(vrf_id);
	struct rte_fib6 *fib;

	if (iface == NULL)
		return NULL;

	fib = vrf_fibs[vrf_id];
	if (fib == NULL) {
		LOG(INFO,
		    "creating IPv6 FIB for VRF %s(%u) max_routes=%u num_tbl8=%u",
		    iface->name,
		    vrf_id,
		    fib6_get_max_routes(vrf_id),
		    fib6_get_num_tbl8(vrf_id));
		fib = create_fib6(vrf_id);
		if (fib == NULL)
			return NULL;
		vrf_fibs[vrf_id] = fib;
	}

	return fib;
}

static inline uintptr_t nh_ptr_to_id(const struct nexthop *nh) {
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

static inline struct nexthop *nh_id_to_ptr(uintptr_t id) {
	return (struct nexthop *)id;
}

const struct nexthop *
fib6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip) {
	struct rte_fib6 *fib6 = get_fib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	struct rte_ipv6_addr tmp;
	uintptr_t nh_id;

	if (fib6 == NULL)
		return NULL;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	rte_fib6_lookup_bulk(fib6, scoped_ip, &nh_id, 1);
	if (nh_id == 0)
		return errno_set_null(EHOSTUNREACH);

	return nh_id_to_ptr(nh_id);
}

struct nexthop *rib6_lookup(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip) {
	struct rte_fib6 *fib6 = get_fib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	struct rte_rib6_node *rn;
	struct rte_ipv6_addr tmp;
	struct rte_rib6 *rib;
	uintptr_t nh_id;

	if (fib6 == NULL)
		return NULL;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	rib = rte_fib6_get_rib(fib6);
	rn = rte_rib6_lookup(rib, scoped_ip);
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
	struct rte_fib6 *fib6 = get_fib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	struct rte_rib6_node *rn;
	struct rte_ipv6_addr tmp;
	struct rte_rib6 *rib;
	uintptr_t nh_id;

	if (fib6 == NULL)
		return NULL;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	rib = rte_fib6_get_rib(fib6);
	rn = rte_rib6_lookup_exact(rib, scoped_ip, prefixlen);
	if (rn == NULL)
		return errno_set_null(ENETUNREACH);

	rte_rib6_get_nh(rn, &nh_id);
	return nh_id_to_ptr(nh_id);
}

struct route6_event {
	struct ip6_net dest;
	uint16_t vrf_id;
	gr_nh_origin_t origin;
	const struct nexthop *nh;
};

static int rib6_insert_or_replace(
	uint16_t vrf_id,
	uint16_t iface_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	struct nexthop *nh,
	bool replace
) {
	struct rte_fib6 *fib = get_or_create_fib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	struct nexthop *existing = NULL;
	struct rte_ipv6_addr tmp;
	struct rte_rib6_node *rn;
	struct rte_rib6 *rib;
	gr_nh_origin_t *o;
	int ret;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);

	if (fib == NULL)
		return -errno;

	if (!nexthop_origin_valid(origin))
		return errno_set(EPFNOSUPPORT);

	rib = rte_fib6_get_rib(fib);

	if ((rn = rte_rib6_lookup_exact(rib, scoped_ip, prefixlen)) != NULL) {
		uintptr_t nh_id;
		rte_rib6_get_nh(rn, &nh_id);
		existing = nh_id_to_ptr(nh_id);
		if (!replace)
			return errno_set(nexthop_equal(nh, existing) ? EEXIST : EBUSY);
	}

	if ((ret = rte_fib6_add(fib, scoped_ip, prefixlen, nh_ptr_to_id(nh))) < 0)
		return errno_set(-ret);

	rn = rte_rib6_lookup_exact(rib, scoped_ip, prefixlen);
	o = rte_rib6_get_ext(rn);
	if (existing) {
		assert(route_counts[vrf_id][*o] > 0);
		route_counts[vrf_id][*o]--;
	}
	*o = origin;
	route_counts[vrf_id][origin]++;

	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP6_ROUTE_ADD,
			&(const struct route6_event) {
				.dest = {*ip, prefixlen},
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
	struct rte_fib6 *fib = get_fib6(vrf_id);
	const struct rte_ipv6_addr *scoped_ip;
	gr_nh_origin_t *o, origin;
	struct rte_ipv6_addr tmp;
	struct rte_rib6_node *rn;
	struct nexthop *nh;
	struct rte_rib6 *rib;
	uintptr_t nh_id;
	int ret;

	if (fib == NULL)
		return -errno;

	scoped_ip = addr6_linklocal_scope(ip, &tmp, iface_id);
	rib = rte_fib6_get_rib(fib);
	rn = rte_rib6_lookup_exact(rib, scoped_ip, prefixlen);
	if (rn == NULL)
		return errno_set(ENOENT);

	o = rte_rib6_get_ext(rn);
	origin = *o;
	rte_rib6_get_nh(rn, &nh_id);
	nh = nh_id_to_ptr(nh_id);
	if (nh->type != nh_type)
		return errno_set(EINVAL);

	if ((ret = rte_fib6_delete(fib, scoped_ip, prefixlen)) < 0)
		return errno_set(-ret);

	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP6_ROUTE_DEL,
			&(const struct route6_event) {
				.dest = {*ip, prefixlen},
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

static struct api_out route6_add(const void *request, struct api_ctx *) {
	const struct gr_ip6_route_add_req *req = request;
	bool created = false;
	struct nexthop *nh;
	int ret;

	if (req->origin == GR_NH_ORIGIN_INTERNAL)
		return api_out(EINVAL, 0, NULL);

	if (req->nh_id != GR_NH_ID_UNSET) {
		nh = nexthop_lookup_id(req->nh_id);
		if (nh == NULL)
			return api_out(ENOENT, 0, NULL);
	} else if ((nh = nexthop_lookup_l3(GR_AF_IP6, req->vrf_id, GR_IFACE_ID_UNDEF, &req->nh))
		   == NULL) {
		// ensure route gateway is reachable
		if ((nh = rib6_lookup(req->vrf_id, GR_IFACE_ID_UNDEF, &req->nh)) == NULL)
			return api_out(EHOSTUNREACH, 0, NULL);

		if (nh->type == GR_NH_T_L3) {
			// if the route gateway is reachable via a prefix route,
			// create a new unresolved nexthop
			struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
			if (!rte_ipv6_addr_eq(&l3->ipv6, &req->nh)) {
				nh = nexthop_new(
					&(struct gr_nexthop_base) {
						.type = GR_NH_T_L3,
						.iface_id = nh->iface_id,
						.vrf_id = req->vrf_id,
						.origin = req->origin,
					},
					&(struct gr_nexthop_info_l3) {
						.af = GR_AF_IP6,
						.ipv6 = req->nh,
					}
				);
				if (nh == NULL)
					return api_out(errno, 0, NULL);
				created = true;
			}
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
	if (ret < 0 && created)
		nexthop_decref(nh);

	return api_out(-ret, 0, NULL);
}

static struct api_out route6_del(const void *request, struct api_ctx *) {
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

	return api_out(-ret, 0, NULL);
}

static struct api_out route6_get(const void *request, struct api_ctx *) {
	const struct gr_ip6_route_get_req *req = request;
	const struct nexthop *nh = NULL;
	struct gr_nexthop *pub = NULL;
	size_t len;

	nh = rib6_lookup(req->vrf_id, GR_IFACE_ID_UNDEF, &req->dest);
	if (nh == NULL)
		return api_out(ENETUNREACH, 0, NULL);

	pub = nexthop_to_api(nh, &len);
	if (pub == NULL)
		return api_out(errno, 0, NULL);

	return api_out(0, len, pub);
}

static void rib6_iter_one(struct rte_rib6 *rib, uint16_t vrf_id, rib6_iter_cb_t cb, void *priv) {
	static const struct rte_ipv6_addr unspec = RTE_IPV6_ADDR_UNSPEC;
	struct rte_rib6_node *rn;
	struct rte_ipv6_addr ip;
	gr_nh_origin_t *origin;
	uint8_t prefixlen;
	uintptr_t nh_id;

	rn = NULL;
	while ((rn = rte_rib6_get_nxt(rib, &unspec, 0, rn, RTE_RIB6_GET_NXT_ALL)) != NULL) {
		rte_rib6_get_ip(rn, &ip);
		rte_rib6_get_depth(rn, &prefixlen);
		origin = rte_rib6_get_ext(rn);
		rte_rib6_get_nh(rn, &nh_id);
		cb(vrf_id, &ip, prefixlen, *origin, nh_id_to_ptr(nh_id), priv);
	}
	// check if there is a default route configured
	if ((rn = rte_rib6_lookup_exact(rib, &unspec, 0)) != NULL) {
		rte_rib6_get_ip(rn, &ip);
		rte_rib6_get_depth(rn, &prefixlen);
		origin = rte_rib6_get_ext(rn);
		rte_rib6_get_nh(rn, &nh_id);
		cb(vrf_id, &ip, prefixlen, *origin, nh_id_to_ptr(nh_id), priv);
	}
}

void rib6_iter(uint16_t vrf_id, rib6_iter_cb_t cb, void *priv) {
	for (uint16_t v = 0; v < GR_MAX_IFACES; v++) {
		if (vrf_fibs[v] == NULL || (v != vrf_id && vrf_id != GR_VRF_ID_UNDEF))
			continue;
		rib6_iter_one(rte_fib6_get_rib(vrf_fibs[v]), v, cb, priv);
	}
}

struct route6_iterator {
	struct api_ctx *ctx;
	int ret;
};

static void route6_list_cb(
	uint16_t vrf_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	const struct nexthop *nh,
	void *priv
) {
	struct route6_iterator *iter = priv;
	if (origin != GR_NH_ORIGIN_INTERNAL && iter->ret == 0) {
		struct gr_ip6_route *r;
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
			r->dest.ip = *ip;
			r->dest.prefixlen = prefixlen;
			r->origin = origin;
			memcpy(&r->nh, pub, nh_len);
			api_send(iter->ctx, len, r);
		} else {
			iter->ret = ENOMEM;
			LOG(ERR, "cannot allocate memory");
		}
		free(pub);
		free(r);
	}
}

static struct api_out route6_list(const void *request, struct api_ctx *ctx) {
	const struct gr_ip6_route_list_req *req = request;
	struct route6_iterator iter = {.ctx = ctx, .ret = 0};

	rib6_iter(req->vrf_id, route6_list_cb, &iter);

	return api_out(iter.ret, 0, NULL);
}

static void route6_init(struct event_base *) {
	vrf_fibs = rte_calloc(
		__func__, GR_MAX_IFACES, sizeof(struct rte_fib6 *), RTE_CACHE_LINE_SIZE
	);
	if (vrf_fibs == NULL)
		ABORT("rte_calloc(vrf_fibs): %s", rte_strerror(rte_errno));
}

static void route6_fini(struct event_base *) {
	for (uint16_t vrf_id = 0; vrf_id < GR_MAX_IFACES; vrf_id++) {
		rte_fib6_free(vrf_fibs[vrf_id]);
		vrf_fibs[vrf_id] = NULL;
	}
	rte_free(vrf_fibs);
	vrf_fibs = NULL;
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
	rib6_iter(GR_VRF_ID_UNDEF, rib6_cleanup_nh, nh);
}

METRIC_GAUGE(m_routes, "rib6_routes", "Number of IPv6 routes by origin.");
METRIC_GAUGE(m_max_routes, "rib6_max_routes", "Maximum number of IPv6 routes.");
#ifdef HAVE_RTE_FIB_TBL8_GET_STATS
METRIC_GAUGE(m_max_tbl8, "fib6_max_tbl8", "Maximum number of IPv6 FIB tbl8 groups.");
METRIC_GAUGE(m_used_tbl8, "fib6_used_tbl8", "Used IPv6 FIB tbl8 groups.");
#endif

static void rib6_metrics_collect(struct gr_metrics_writer *w) {
	struct gr_metrics_ctx ctx;
	char vrf[16];

	for (uint16_t vrf_id = 0; vrf_id < GR_MAX_IFACES; vrf_id++) {
		if (vrf_fibs[vrf_id] == NULL)
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
		gr_metric_emit(&ctx, &m_max_routes, fib6_get_max_routes(vrf_id));
#ifdef HAVE_RTE_FIB_TBL8_GET_STATS
		uint32_t used_tbl8, total_tbl8;
		rte_fib6_tbl8_get_stats(vrf_fibs[vrf_id], &used_tbl8, &total_tbl8);
		gr_metric_emit(&ctx, &m_max_tbl8, total_tbl8);
		gr_metric_emit(&ctx, &m_used_tbl8, used_tbl8);
#endif
	}
}

static struct gr_metrics_collector rib6_collector = {
	.name = "rib6",
	.collect = rib6_metrics_collect,
};

static int serialize_route6_event(const void *obj, void **buf) {
	const struct route6_event *priv = obj;
	struct gr_ip6_route *r;
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

struct fib6_migrate_ctx {
	struct rte_fib6 *new_fib;
	uint32_t counts[UINT_NUM_VALUES(gr_nh_origin_t)];
};

static void fib6_migrate_cb(
	uint16_t vrf_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	const struct nexthop *nh,
	void *priv
) {
	struct fib6_migrate_ctx *ctx = priv;
	int ret;

	ret = rte_fib6_add(ctx->new_fib, ip, prefixlen, nh_ptr_to_id(nh));
	if (ret < 0) {
		if (nh->type == GR_NH_T_L3 && (nexthop_info_l3(nh)->flags & NH_LOCAL_ADDR_FLAGS)) {
			const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
			LOG(WARNING,
			    "iface %u: dropping local address " IP6_F "/%hhu: %s",
			    nh->iface_id,
			    &l3->ipv6,
			    l3->prefixlen,
			    rte_strerror(-ret));
			addr6_delete(nh->iface_id, &l3->ipv6, l3->prefixlen);
		} else {
			LOG(WARNING,
			    "vrf %u: dropping route " IP6_F "/%hhu: %s",
			    vrf_id,
			    ip,
			    prefixlen,
			    rte_strerror(-ret));
			if (origin != GR_NH_ORIGIN_INTERNAL) {
				gr_event_push(
					GR_EVENT_IP6_ROUTE_DEL,
					&(const struct route6_event) {
						.dest = {*ip, prefixlen},
						.vrf_id = vrf_id,
						.origin = origin,
						.nh = nh,
					}
				);
			}
			nexthop_decref((struct nexthop *)nh);
		}
		return;
	}

	struct rte_rib6 *rib = rte_fib6_get_rib(ctx->new_fib);
	struct rte_rib6_node *rn = rte_rib6_lookup_exact(rib, ip, prefixlen);
	gr_nh_origin_t *o = rte_rib6_get_ext(rn);
	*o = origin;
	ctx->counts[origin]++;
}

static uint32_t fib6_total_routes(uint16_t vrf_id) {
	uint32_t total = 0;
	for (unsigned o = 0; o < UINT_NUM_VALUES(gr_nh_origin_t); o++)
		total += route_counts[vrf_id][o];
	return total;
}

static struct api_out fib6_conf_set(const void *request, struct api_ctx *) {
	const struct gr_ip6_fib_conf_set_req *req = request;
	uint32_t old_max, old_tbl8, new_max, new_tbl8;
	struct rte_fib6 *old_fib, *new_fib;
	const struct iface *vrf;

	if (req->vrf_id == GR_VRF_ID_UNDEF) {
		if (req->max_routes == 0)
			return api_out(EINVAL, 0, NULL);
		if (req->max_routes != max_routes_default) {
			LOG(INFO,
			    "changing default max_routes %u -> %u num_tbl8 %u -> %u",
			    max_routes_default,
			    req->max_routes,
			    fib6_auto_tbl8(max_routes_default),
			    fib6_auto_tbl8(req->max_routes));
			max_routes_default = req->max_routes;
		}
		return api_out(0, 0, NULL);
	}

	if (req->vrf_id >= GR_MAX_IFACES)
		return api_out(EOVERFLOW, 0, NULL);

	old_max = fib6_get_max_routes(req->vrf_id);
	old_tbl8 = fib6_get_num_tbl8(req->vrf_id);
	new_max = req->max_routes ?: old_max;
	new_tbl8 = req->num_tbl8 ?: fib6_auto_tbl8(new_max);
	old_fib = vrf_fibs[req->vrf_id];

	if (new_max == old_max && new_tbl8 && old_tbl8 && old_fib != NULL)
		return api_out(0, 0, NULL);

	fib6_conf[req->vrf_id].max_routes = new_max;
	fib6_conf[req->vrf_id].num_tbl8 = new_tbl8;

	if (old_fib == NULL)
		return api_out(0, 0, NULL);

	vrf = get_vrf_iface(req->vrf_id);

	LOG(INFO,
	    "resizing IPv6 FIB VRF %s(%u) max_routes %u -> %u num_tbl8 %u -> %u",
	    vrf ? vrf->name : "?",
	    req->vrf_id,
	    old_max,
	    new_max,
	    old_tbl8,
	    new_tbl8);

	new_fib = create_fib6(req->vrf_id);
	if (new_fib == NULL)
		return api_out(errno, 0, NULL);

	struct fib6_migrate_ctx ctx = {.new_fib = new_fib};
	rib6_iter(req->vrf_id, fib6_migrate_cb, &ctx);

	vrf_fibs[req->vrf_id] = new_fib;
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
	rte_fib6_free(old_fib);

	memcpy(route_counts[req->vrf_id], ctx.counts, sizeof(ctx.counts));

	return api_out(0, 0, NULL);
}

static struct api_out fib6_info_list(const void *request, struct api_ctx *ctx) {
	const struct gr_ip6_fib_info_list_req *req = request;
	struct gr_fib6_info info;

	info.vrf_id = GR_VRF_ID_UNDEF;
	info.max_routes = max_routes_default;
	info.used_routes = 0;
	info.num_tbl8 = fib6_auto_tbl8(max_routes_default);
	info.used_tbl8 = 0;
	api_send(ctx, sizeof(info), &info);

	for (uint16_t v = 0; v < GR_MAX_IFACES; v++) {
		if (v != req->vrf_id && req->vrf_id != GR_VRF_ID_UNDEF)
			continue;
		if (vrf_fibs[v] == NULL)
			continue;
		info.vrf_id = v;
		info.max_routes = fib6_get_max_routes(v);
		info.used_routes = fib6_total_routes(v);
#ifdef HAVE_RTE_FIB_TBL8_GET_STATS
		rte_fib6_tbl8_get_stats(vrf_fibs[v], &info.used_tbl8, &info.num_tbl8);
#else
		info.num_tbl8 = fib6_get_num_tbl8(v);
		info.used_tbl8 = 0;
#endif
		api_send(ctx, sizeof(info), &info);
	}

	return api_out(0, 0, NULL);
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
static struct gr_api_handler fib6_conf_set_handler = {
	.name = "ipv6 fib conf set",
	.request_type = GR_IP6_FIB_CONF_SET,
	.callback = fib6_conf_set,
};
static struct gr_api_handler fib6_info_list_handler = {
	.name = "ipv6 fib info list",
	.request_type = GR_IP6_FIB_INFO_LIST,
	.callback = fib6_info_list,
};

static struct gr_event_serializer route6_serializer = {
	.callback = serialize_route6_event,
	.ev_count = 2,
	.ev_types = {GR_EVENT_IP6_ROUTE_ADD, GR_EVENT_IP6_ROUTE_DEL},
};

static struct gr_module route6_module = {
	.name = "ipv6 route",
	.depends_on = "nexthop",
	.init = route6_init,
	.fini = route6_fini,
};

static void route6_vrf_rm(
	uint16_t vrf_id,
	const struct rte_ipv6_addr *ip,
	uint8_t depth,
	gr_nh_origin_t origin,
	const struct nexthop *nh,
	void *priv
) {
	const struct iface *vrf = priv;

	LOG(DEBUG, "VRF %s(%u): " IP6_F "/%hhu", vrf->name, vrf->id, ip, depth);

	if (origin != GR_NH_ORIGIN_INTERNAL) {
		gr_event_push(
			GR_EVENT_IP6_ROUTE_DEL,
			&(const struct route6_event) {
				.dest = {*ip, depth},
				.vrf_id = vrf_id,
				.origin = origin,
				.nh = nh,
			}
		);
	}
	nexthop_decref((void *)nh);
}

static void iface_rm_cb(uint32_t /*ev_type*/, const void *obj) {
	const struct iface *iface = obj;
	struct rte_fib6 *fib;

	if (iface->type != GR_IFACE_TYPE_VRF)
		return;

	memset(&fib6_conf[iface->id], 0, sizeof(fib6_conf[0]));
	fib = vrf_fibs[iface->id];
	vrf_fibs[iface->id] = NULL;
	if (fib != NULL) {
		LOG(INFO, "destroying IPv6 FIB for VRF %s(%u)", iface->name, iface->id);
		rib6_iter_one(rte_fib6_get_rib(fib), iface->id, route6_vrf_rm, (void *)iface);
		rte_fib6_free(fib);
	}
	memset(route_counts[iface->id], 0, sizeof(route_counts[iface->id]));
}

static struct gr_event_subscription iface_subscription = {
	.callback = iface_rm_cb,
	.ev_count = 1,
	.ev_types = {GR_EVENT_IFACE_REMOVE},
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&route6_add_handler);
	gr_register_api_handler(&route6_del_handler);
	gr_register_api_handler(&route6_get_handler);
	gr_register_api_handler(&route6_list_handler);
	gr_register_api_handler(&fib6_conf_set_handler);
	gr_register_api_handler(&fib6_info_list_handler);
	gr_event_register_serializer(&route6_serializer);
	gr_register_module(&route6_module);
	gr_metrics_register(&rib6_collector);
	gr_event_subscribe(&iface_subscription);
}
