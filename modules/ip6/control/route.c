// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "iface.h"
#include "ip6.h"
#include "module.h"
#include "rcu.h"
#include "vrf.h"

#include <gr_event.h>
#include <gr_infra.h>
#include <gr_ip6.h>
#include <gr_log.h>
#include <gr_metrics.h>
#include <gr_net_types.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_fib6.h>
#include <rte_rib6.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

GR_LOG_TYPE("route");

static uint32_t route_counts[GR_MAX_IFACES][UINT_NUM_VALUES(gr_nh_origin_t)];

static uint32_t max_routes_default = 1 << 16;

// Derive num_tbl8 from max_routes for IPv6 TRIE.
// The trie uses 8-bit levels beyond the first 24 bits. IPv6 routes at
// /48 consume up to 3 tbl8 groups each. Sharing reduces actual usage
// but a ratio of 4x is needed to handle real-world prefix distributions
// without exhaustion.
static inline uint32_t fib6_auto_tbl8(uint32_t max_routes) {
	uint32_t n = max_routes * 4;
	return n < 256 ? 256 : n;
}

static inline uint32_t fib6_get_max_routes(const struct iface *vrf) {
	return iface_info_vrf(vrf)->ipv6.max_routes;
}

static inline uint32_t fib6_get_num_tbl8(const struct iface *vrf) {
	return iface_info_vrf(vrf)->ipv6.num_tbl8;
}

static struct rte_fib6 *get_fib6(uint16_t vrf_id) {
	struct iface *iface = get_vrf_iface(vrf_id);
	if (iface == NULL)
		return NULL;

	struct rte_fib6 *fib = iface_info_vrf(iface)->fib6;
	if (fib == NULL)
		return errno_set_null(ENONET);

	return fib;
}

static struct rte_fib6 *create_fib6(const struct iface *vrf) {
	struct rte_fib6_conf conf = {
		.type = RTE_FIB6_TRIE,
		.default_nh = 0,
		.max_routes = fib6_get_max_routes(vrf),
		.rib_ext_sz = sizeof(gr_nh_origin_t),
		.trie = {
			.nh_sz = RTE_FIB6_TRIE_8B,
			.num_tbl8 = fib6_get_num_tbl8(vrf),
		},
	};
	struct rte_fib6 *fib;
	static unsigned seq;
	char name[16];
	int ret;

	snprintf(name, sizeof(name), "fib6_%x-%x", vrf->id, seq++);
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

static int fib6_init(struct iface *vrf) {
	struct gr_iface_info_vrf_fib *conf = &iface_info_vrf(vrf)->ipv6;
	struct rte_fib6 *fib;

	if (!conf->max_routes)
		conf->max_routes = max_routes_default;
	if (!conf->num_tbl8)
		conf->num_tbl8 = fib6_auto_tbl8(conf->max_routes);

	LOG(INFO,
	    "creating IPv6 FIB for VRF %s(%u) max_routes=%u num_tbl8=%u",
	    vrf->name,
	    vrf->id,
	    conf->max_routes,
	    conf->num_tbl8);

	fib = create_fib6(vrf);
	if (fib == NULL)
		return errno_log(errno, "create_fib6");

	iface_info_vrf(vrf)->fib6 = fib;
	return 0;
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
	struct rte_fib6 *fib = get_fib6(vrf_id);
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

	LOG(DEBUG, "VRF %u: " IP6_F "/%hhu", vrf_id, ip, prefixlen);
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
	if ((ret == -ENOENT || ret == -ENONET) && req->missing_ok)
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

static int rib6_iter_route(struct rte_rib6_node *rn, uint16_t vrf_id, struct rib6_iterator *iter) {
	struct rte_ipv6_addr ip;
	gr_nh_origin_t *origin;
	uint8_t prefixlen;
	uintptr_t nh_id;
	int ret;

	origin = rte_rib6_get_ext(rn);
	if (iter->skip_internal && *origin == GR_NH_ORIGIN_INTERNAL)
		return 0;

	if (iter->max_count != 0 && iter->count >= iter->max_count)
		return errno_set(EXFULL);

	rte_rib6_get_ip(rn, &ip);
	rte_rib6_get_depth(rn, &prefixlen);
	rte_rib6_get_nh(rn, &nh_id);

	ret = iter->cb(vrf_id, &ip, prefixlen, *origin, nh_id_to_ptr(nh_id), iter->priv);
	if (ret < 0)
		return ret;

	iter->count++;

	return 0;
}
static int rib6_iter_vrf(struct rte_rib6 *rib, uint16_t vrf_id, struct rib6_iterator *iter) {
	static const struct rte_ipv6_addr unspec = RTE_IPV6_ADDR_UNSPEC;
	struct rte_rib6_node *rn;

	rn = NULL;
	while ((rn = rte_rib6_get_nxt(rib, &unspec, 0, rn, RTE_RIB6_GET_NXT_ALL)) != NULL) {
		if (rib6_iter_route(rn, vrf_id, iter) < 0)
			return -errno;
	}
	// check if there is a default route configured
	if ((rn = rte_rib6_lookup_exact(rib, &unspec, 0)) != NULL) {
		if (rib6_iter_route(rn, vrf_id, iter) < 0)
			return -errno;
	}

	return 0;
}

int rib6_iter(uint16_t vrf_id, struct rib6_iterator *iter) {
	for (uint16_t v = 0; v < GR_MAX_IFACES; v++) {
		if (v != vrf_id && vrf_id != GR_VRF_ID_UNDEF)
			continue;
		struct iface *iface = get_vrf_iface(v);
		if (iface == NULL)
			continue;
		struct rte_fib6 *fib = iface_info_vrf(iface)->fib6;
		if (fib == NULL)
			continue;
		if (rib6_iter_vrf(rte_fib6_get_rib(fib), v, iter) < 0)
			return -errno;
	}
	return 0;
}

static int route6_list_cb(
	uint16_t vrf_id,
	const struct rte_ipv6_addr *ip,
	uint8_t prefixlen,
	gr_nh_origin_t origin,
	const struct nexthop *nh,
	void *priv
) {
	struct api_ctx *ctx = priv;
	struct gr_ip6_route *r;
	struct gr_nexthop *pub;
	size_t nh_len, len;

	pub = nexthop_to_api(nh, &nh_len);
	if (pub == NULL)
		return -errno;

	len = sizeof(*r) - sizeof(r->nh) + nh_len;
	r = malloc(len);
	if (r == NULL)
		return -errno;

	r->vrf_id = vrf_id;
	r->dest.ip = *ip;
	r->dest.prefixlen = prefixlen;
	r->origin = origin;
	memcpy(&r->nh, pub, nh_len);
	api_send(ctx, len, r);
	free(pub);
	free(r);

	return 0;
}

static struct api_out route6_list(const void *request, struct api_ctx *ctx) {
	const struct gr_ip6_route_list_req *req = request;
	struct rib6_iterator iter = {
		.max_count = req->max_count,
		.skip_internal = true,
		.cb = route6_list_cb,
		.priv = ctx,
	};
	int ret = rib6_iter(req->vrf_id, &iter);
	return api_out(-ret, 0, NULL);
}

struct rib6_cleanup_entry {
	uint16_t vrf_id;
	uint16_t iface_id;
	struct rte_ipv6_addr ip;
	uint8_t depth;
	gr_nh_type_t type;
};

struct rib6_cleanup_ctx {
	const struct nexthop *nh;
	gr_vec struct rib6_cleanup_entry *entries;
};

static int rib6_cleanup_cb(
	uint16_t vrf_id,
	const struct rte_ipv6_addr *ip,
	uint8_t depth,
	gr_nh_origin_t,
	const struct nexthop *nh,
	void *priv
) {
	struct rib6_cleanup_ctx *ctx = priv;
	if (ctx->nh == NULL || nh == ctx->nh) {
		struct rib6_cleanup_entry entry = {
			.vrf_id = vrf_id,
			.iface_id = nh->iface_id,
			.ip = *ip,
			.depth = depth,
			.type = nh->type,
		};
		gr_vec_add(ctx->entries, entry);
	}
	return 0;
}

void rib6_cleanup(struct nexthop *nh) {
	struct rib6_cleanup_ctx ctx = {
		.nh = nh,
		.entries = NULL,
	};
	struct rib6_iterator iter = {
		.max_count = 0,
		.skip_internal = false,
		.cb = rib6_cleanup_cb,
		.priv = &ctx,
	};
	rib6_iter(GR_VRF_ID_UNDEF, &iter);
	gr_vec_foreach_ref (const struct rib6_cleanup_entry *r, ctx.entries)
		rib6_delete(r->vrf_id, r->iface_id, &r->ip, r->depth, r->type);
	gr_vec_free(ctx.entries);
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
		gr_metric_emit(&ctx, &m_max_routes, fib6_get_max_routes(vrf_iface));
#ifdef HAVE_RTE_FIB_TBL8_GET_STATS
		uint32_t used_tbl8, total_tbl8;
		struct rte_fib6 *fib = iface_info_vrf(vrf_iface)->fib6;
		if (fib != NULL) {
			rte_fib6_tbl8_get_stats(fib, &used_tbl8, &total_tbl8);
			gr_metric_emit(&ctx, &m_max_tbl8, total_tbl8);
			gr_metric_emit(&ctx, &m_used_tbl8, used_tbl8);
		}
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

static int fib6_migrate_cb(
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
		return 0;
	}

	struct rte_rib6 *rib = rte_fib6_get_rib(ctx->new_fib);
	struct rte_rib6_node *rn = rte_rib6_lookup_exact(rib, ip, prefixlen);
	gr_nh_origin_t *o = rte_rib6_get_ext(rn);
	*o = origin;
	ctx->counts[origin]++;

	return 0;
}

static uint32_t fib6_total_routes(uint16_t vrf_id) {
	uint32_t total = 0;
	for (unsigned o = 0; o < UINT_NUM_VALUES(gr_nh_origin_t); o++)
		total += route_counts[vrf_id][o];
	return total;
}

static int fib6_reconfig(struct iface *vrf) {
	struct gr_iface_info_vrf_fib *conf = &iface_info_vrf(vrf)->ipv6;
	struct rte_fib6 *old_fib, *new_fib;

	if (!conf->max_routes)
		conf->max_routes = max_routes_default;
	if (!conf->num_tbl8)
		conf->num_tbl8 = fib6_auto_tbl8(conf->max_routes);

	old_fib = iface_info_vrf(vrf)->fib6;
	new_fib = create_fib6(vrf);
	if (new_fib == NULL)
		return errno_log(errno, "create_fib6");

	struct fib6_migrate_ctx ctx = {.new_fib = new_fib};
	struct rib6_iterator iter = {
		.max_count = 0,
		.skip_internal = false,
		.cb = fib6_migrate_cb,
		.priv = &ctx,
	};
	rib6_iter_vrf(rte_fib6_get_rib(old_fib), vrf->id, &iter);

	iface_info_vrf(vrf)->fib6 = new_fib;
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
	rte_fib6_free(old_fib);

	memcpy(route_counts[vrf->id], ctx.counts, sizeof(ctx.counts));

	return 0;
}

static struct api_out fib6_info_list(const void *request, struct api_ctx *ctx) {
	const struct gr_ip6_fib_info_list_req *req = request;
	struct gr_fib6_info info;

	if (req->vrf_id == GR_VRF_ID_UNDEF) {
		info.vrf_id = GR_VRF_ID_UNDEF;
		info.max_routes = max_routes_default;
		info.used_routes = 0;
		info.num_tbl8 = fib6_auto_tbl8(max_routes_default);
		info.used_tbl8 = 0;
		api_send(ctx, sizeof(info), &info);
	}

	for (uint16_t v = 0; v < GR_MAX_IFACES; v++) {
		if (v != req->vrf_id && req->vrf_id != GR_VRF_ID_UNDEF)
			continue;
		const struct iface *vrf = get_vrf_iface(v);
		if (vrf == NULL)
			continue;
		info.vrf_id = v;
		info.max_routes = fib6_get_max_routes(vrf);
		info.used_routes = fib6_total_routes(v);
#ifdef HAVE_RTE_FIB_TBL8_GET_STATS
		struct rte_fib6 *fib = iface_info_vrf(vrf)->fib6;
		if (fib != NULL)
			rte_fib6_tbl8_get_stats(fib, &info.used_tbl8, &info.num_tbl8);
#else
		info.num_tbl8 = fib6_get_num_tbl8(vrf);
		info.used_tbl8 = 0;
#endif
		api_send(ctx, sizeof(info), &info);
	}

	return api_out(0, 0, NULL);
}

static struct gr_module route6_module = {
	.name = "ip6_route",
	.depends_on = "nexthop",
};

static void fib6_fini(struct iface *vrf) {
	struct rte_fib6 *fib = iface_info_vrf(vrf)->fib6;
	if (fib != NULL) {
		LOG(INFO, "destroying IPv6 FIB for VRF %s(%u)", vrf->name, vrf->id);
		struct rib6_cleanup_ctx ctx = {
			.nh = NULL,
			.entries = NULL,
		};
		struct rib6_iterator iter = {
			.max_count = 0,
			.skip_internal = false,
			.cb = rib6_cleanup_cb,
			.priv = &ctx,
		};
		rib6_iter_vrf(rte_fib6_get_rib(fib), vrf->id, &iter);

		gr_vec_foreach_ref (const struct rib6_cleanup_entry *r, ctx.entries)
			rib6_delete(r->vrf_id, r->iface_id, &r->ip, r->depth, r->type);
		gr_vec_free(ctx.entries);

		iface_info_vrf(vrf)->fib6 = NULL;

		rte_fib6_free(fib);
	}
	memset(route_counts[vrf->id], 0, sizeof(route_counts[vrf->id]));
}

static struct api_out fib6_default_set(const void *request, struct api_ctx *) {
	const struct gr_ip6_fib_default_set_req *req = request;

	if (req->max_routes == 0)
		return api_out(EINVAL, 0, NULL);

	if (req->max_routes != max_routes_default) {
		LOG(INFO, "IPv6 default max_routes %u -> %u", max_routes_default, req->max_routes);
		max_routes_default = req->max_routes;
	}

	return api_out(0, 0, NULL);
}

static const struct vrf_fib_ops fib6_ops = {
	.init = fib6_init,
	.reconfig = fib6_reconfig,
	.fini = fib6_fini,
};

RTE_INIT(control_ip_init) {
	gr_api_handler(GR_IP6_ROUTE_ADD, route6_add);
	gr_api_handler(GR_IP6_ROUTE_DEL, route6_del);
	gr_api_handler(GR_IP6_ROUTE_GET, route6_get);
	gr_api_handler(GR_IP6_ROUTE_LIST, route6_list);
	gr_api_handler(GR_IP6_FIB_DEFAULT_SET, fib6_default_set);
	gr_api_handler(GR_IP6_FIB_INFO_LIST, fib6_info_list);
	gr_event_serializer(GR_EVENT_IP6_ROUTE_ADD, serialize_route6_event, 0);
	gr_event_serializer(GR_EVENT_IP6_ROUTE_DEL, serialize_route6_event, 0);
	gr_register_module(&route6_module);
	gr_metrics_register(&rib6_collector);
	vrf_fib_ops_register(GR_AF_IP6, &fib6_ops);
}
