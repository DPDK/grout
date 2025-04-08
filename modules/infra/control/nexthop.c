// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_clock.h>
#include <gr_event.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_module.h>
#include <gr_nh_control.h>

#include <rte_malloc.h>
#include <rte_mempool.h>

#include <stdint.h>

#define DEFAULT_MAX_COUNT (1 << 17)
#define DEFAULT_MAX_HELD_PKTS 256
#define DEFAULT_LIFETIME_REACHABLE (20 * 60)
#define DEFAULT_LIFETIME_UNREACHABLE 60
#define DEFAULT_UCAST_PROBES 3
#define DEFAULT_BCAST_PROBES 3

static struct rte_mempool *pool;
static struct event *ageing_timer;
static const struct nexthop_ops *nh_ops[GR_NH_TYPE_COUNT];
struct gr_nexthop_config nh_conf = {
	.max_count = DEFAULT_MAX_COUNT,
	.lifetime_reachable_sec = DEFAULT_LIFETIME_REACHABLE,
	.lifetime_unreachable_sec = DEFAULT_LIFETIME_UNREACHABLE,
	.max_held_pkts = DEFAULT_MAX_HELD_PKTS,
	.max_ucast_probes = DEFAULT_UCAST_PROBES,
	.max_bcast_probes = DEFAULT_BCAST_PROBES,
};

void nexthop_ops_register(gr_nh_type_t type, const struct nexthop_ops *ops) {
	switch (type) {
	case GR_NH_IPV4:
	case GR_NH_IPV6:
		break;
	default:
		ABORT("invalid nexthop type %hhu", type);
	}
	if (ops == NULL || ops->free == NULL || ops->solicit == NULL)
		ABORT("invalid ops");
	nh_ops[type] = ops;
}

struct nexthop *
nexthop_new(gr_nh_type_t type, uint16_t vrf_id, uint16_t iface_id, const void *addr) {
	struct nexthop *nh;
	void *data;
	int ret;

	if (rte_lcore_has_role(rte_lcore_id(), ROLE_NON_EAL))
		ABORT("nexthop created from datapath thread");

	if ((ret = rte_mempool_get(pool, &data)) < 0)
		return errno_set_null(-ret);

	nh = data;
	nh->vrf_id = vrf_id;
	nh->iface_id = iface_id;
	nh->type = type;
	switch (type) {
	case GR_NH_IPV4:
	case GR_NH_SR6_IPV4:
		nh->ipv4 = *(ip4_addr_t *)addr;
		break;
	case GR_NH_IPV6:
	case GR_NH_SR6_IPV6:
		nh->ipv6 = *(struct rte_ipv6_addr *)addr;
		break;
	default:
		ABORT("invalid nexthop type %hhu", type);
	}

	gr_event_push(NEXTHOP_EVENT_NEW, nh);

	return nh;
}

struct pool_iterator {
	nh_iter_cb_t user_cb;
	void *priv;
};

static void nh_pool_iter_cb(struct rte_mempool *, void *priv, void *obj, unsigned /*obj_idx*/) {
	struct pool_iterator *it = priv;
	struct nexthop *nh = obj;
	if (nh->ref_count != 0)
		it->user_cb(nh, it->priv);
	else
		assert(rte_lcore_has_role(rte_lcore_id(), ROLE_NON_EAL)
		       || rte_ipv6_addr_is_unspec(&nh->ipv6));
}

void nexthop_iter(nh_iter_cb_t nh_cb, void *priv) {
	struct pool_iterator it = {
		.user_cb = nh_cb,
		.priv = priv,
	};
	rte_mempool_obj_iter(pool, nh_pool_iter_cb, &it);
}

struct lookup_filter {
	gr_nh_type_t type;
	uint16_t vrf_id;
	uint16_t iface_id;
	const void *addr;
	struct nexthop *nh;
};

static void nh_lookup_cb(struct nexthop *nh, void *priv) {
	struct lookup_filter *filter = priv;

	if (filter->nh != NULL || nh->type != filter->type || nh->vrf_id != filter->vrf_id)
		return;

	switch (filter->type) {
	case GR_NH_IPV4:
	case GR_NH_SR6_IPV4:
		if (nh->ipv4 == *(ip4_addr_t *)filter->addr)
			filter->nh = nh;
		break;
	case GR_NH_IPV6:
	case GR_NH_SR6_IPV6:
		if (rte_ipv6_addr_eq(&nh->ipv6, filter->addr)) {
			bool is_linklocal = rte_ipv6_addr_is_linklocal(&nh->ipv6);
			if (!is_linklocal || nh->iface_id == filter->iface_id)
				filter->nh = nh;
		}
		break;
	case GR_NH_TYPE_COUNT:
		break;
	}
}

struct nexthop *
nexthop_lookup(gr_nh_type_t type, uint16_t vrf_id, uint16_t iface_id, const void *addr) {
	struct lookup_filter filter = {
		.type = type, .vrf_id = vrf_id, .iface_id = iface_id, .addr = addr
	};
	nexthop_iter(nh_lookup_cb, &filter);
	return filter.nh ?: errno_set_null(ENOENT);
}

void nexthop_decref(struct nexthop *nh) {
	if (nh->ref_count <= 1) {
		// Flush all held packets.
		struct rte_mbuf *m = nh->held_pkts_head;
		while (m != NULL) {
			struct rte_mbuf *next = queue_mbuf_data(m)->next;
			rte_pktmbuf_free(m);
			m = next;
		}
		gr_event_push(NEXTHOP_EVENT_DELETE, nh);
		memset(nh, 0, sizeof(*nh));
		rte_mempool_put(pool, nh);
	} else {
		nh->ref_count--;
	}
}

void nexthop_incref(struct nexthop *nh) {
	nh->ref_count++;
}

static void nexthop_ageing_cb(struct nexthop *nh, void *) {
	const struct nexthop_ops *ops = nh_ops[nh->type];
	clock_t now = gr_clock_us();
	time_t reply_age, request_age;
	unsigned probes, max_probes;

	if (nh->flags & GR_NH_F_STATIC)
		return;

	reply_age = (now - nh->last_reply) / CLOCKS_PER_SEC;
	request_age = (now - nh->last_request) / CLOCKS_PER_SEC;
	max_probes = nh_conf.max_ucast_probes + nh_conf.max_bcast_probes;
	probes = nh->ucast_probes + nh->bcast_probes;

	if (nh->flags & (GR_NH_F_PENDING | GR_NH_F_STALE)) {
		if (probes >= max_probes) {
			LOG(DEBUG,
			    ADDR_F " vrf=%u failed_probes=%u held_pkts=%u: %s -> failed",
			    ADDR_W(nh_af(&nh->base)),
			    &nh->addr,
			    nh->vrf_id,
			    probes,
			    nh->held_pkts,
			    gr_nh_flag_name(nh->flags & (GR_NH_F_PENDING | GR_NH_F_STALE)));

			nh->flags &= ~(GR_NH_F_PENDING | GR_NH_F_STALE);
			nh->flags |= GR_NH_F_FAILED;
		} else {
			if (ops->solicit(nh) < 0)
				LOG(ERR,
				    ADDR_F " vrf=%u solicit failed: %s",
				    ADDR_W(nh_af(&nh->base)),
				    &nh->addr,
				    nh->vrf_id,
				    strerror(errno));
		}
	} else if (nh->flags & GR_NH_F_REACHABLE && reply_age > nh_conf.lifetime_reachable_sec) {
		nh->flags &= ~GR_NH_F_REACHABLE;
		nh->flags |= GR_NH_F_STALE;
	} else if (nh->flags & GR_NH_F_FAILED && request_age > nh_conf.lifetime_unreachable_sec) {
		LOG(DEBUG,
		    ADDR_F " vrf=%u failed_probes=%u held_pkts=%u: failed -> <destroy>",
		    ADDR_W(nh_af(&nh->base)),
		    &nh->addr,
		    nh->vrf_id,
		    probes,
		    nh->held_pkts);
		ops->free(nh);
	}
}

static void do_ageing(evutil_socket_t, short /*what*/, void * /*priv*/) {
	nexthop_iter(nexthop_ageing_cb, NULL);
}

static void nh_init(struct event_base *ev_base) {
	pool = rte_mempool_create(
		"nexthops",
		rte_align32pow2(nh_conf.max_count) - 1,
		sizeof(struct nexthop),
		0, // cache size
		0, // priv size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		SOCKET_ID_ANY,
		0 // flags
	);
	if (pool == NULL)
		ABORT("rte_mempool_create(nexthops) failed");

	ageing_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, do_ageing, NULL);
	if (ageing_timer == NULL)
		ABORT("event_new() failed");

	if (event_add(ageing_timer, &(struct timeval) {.tv_sec = 1}) < 0)
		ABORT("event_add() failed");
}

static void nh_fini(struct event_base *) {
	if (ageing_timer)
		event_free(ageing_timer);
	rte_mempool_free(pool);
}

static struct gr_event_serializer nh_serializer = {
	.size = sizeof(struct gr_nexthop),
	.ev_count = 3,
	.ev_types = {
		NEXTHOP_EVENT_NEW,
		NEXTHOP_EVENT_DELETE,
		NEXTHOP_EVENT_UPDATE,
	},
};

static struct gr_module module = {
	.name = "nexthop",
	.init = nh_init,
	.fini = nh_fini,
	.fini_prio = 20000,
};

RTE_INIT(init) {
	gr_event_register_serializer(&nh_serializer);
	gr_register_module(&module);
}
