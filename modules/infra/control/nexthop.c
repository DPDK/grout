// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_clock.h>
#include <gr_event.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_nh_control.h>

#include <rte_malloc.h>
#include <rte_mempool.h>

#include <stdint.h>

struct nh_pool {
	struct rte_mempool *mp;
	struct event *ageing_timer;
	nh_solicit_cb_t solicit_nh;
	nh_free_cb_t free_nh;
	unsigned num_nexthops;
	uint8_t family;
};

static void nh_pool_do_ageing(evutil_socket_t, short, void *);

struct nh_pool *
nh_pool_new(uint8_t family, struct event_base *ev_base, const struct nh_pool_opts *opts) {
	struct nh_pool *nhp;
	const char *name;

	if (opts == NULL || ev_base == NULL || opts->num_nexthops == 0 || opts->free_nh == NULL
	    || opts->solicit_nh == NULL)
		ABORT("invalid arguments");

	switch (family) {
	case AF_INET:
		name = "ipv4-nexthops";
		break;
	case AF_INET6:
		name = "ipv6-nexthops";
		break;
	default:
		ABORT("unsupported address family: %hhu", family);
	}

	nhp = rte_zmalloc(name, sizeof(*nhp), alignof(struct nh_pool));
	if (nhp == NULL) {
		LOG(ERR, "rte_zmalloc() failed");
		return errno_set_null(ENOMEM);
	}

	nhp->family = family;
	nhp->free_nh = opts->free_nh;
	nhp->solicit_nh = opts->solicit_nh;
	nhp->num_nexthops = rte_align32pow2(opts->num_nexthops) - 1;
	nhp->mp = rte_mempool_create(
		name,
		nhp->num_nexthops,
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
	if (nhp->mp == NULL) {
		nh_pool_free(nhp);
		return errno_set_null(ENOMEM);
	}

	nhp->ageing_timer = event_new(
		ev_base, -1, EV_PERSIST | EV_FINALIZE, nh_pool_do_ageing, nhp
	);
	if (nhp->ageing_timer == NULL) {
		LOG(ERR, "event_new() failed");
		nh_pool_free(nhp);
		return errno_set_null(ENOMEM);
	}

	if (event_add(nhp->ageing_timer, &(struct timeval) {.tv_sec = 1}) < 0) {
		LOG(ERR, "event_add() failed");
		nh_pool_free(nhp);
		return errno_set_null(ENOMEM);
	}

	return nhp;
}

void nh_pool_free(struct nh_pool *nhp) {
	if (nhp == NULL)
		return;
	if (nhp->ageing_timer)
		event_free(nhp->ageing_timer);
	if (nhp->mp)
		rte_mempool_free(nhp->mp);
	rte_free(nhp);
}

struct nexthop *
nexthop_new(struct nh_pool *nhp, uint16_t vrf_id, uint16_t iface_id, const void *addr) {
	struct nexthop *nh;
	void *data;
	int ret;

	if (rte_lcore_has_role(rte_lcore_id(), ROLE_NON_EAL))
		ABORT("nexthop created from datapath thread");

	if (nhp == NULL)
		ABORT("nhp == NULL");

	if ((ret = rte_mempool_get(nhp->mp, &data)) < 0)
		return errno_set_null(-ret);

	nh = data;
	nh->vrf_id = vrf_id;
	nh->iface_id = iface_id;
	nh->family = nhp->family;
	switch (nhp->family) {
	case AF_INET:
		nh->ipv4 = *(ip4_addr_t *)addr;
		break;
	case AF_INET6:
		nh->ipv6 = *(struct rte_ipv6_addr *)addr;
		break;
	}
	nh->pool = nhp;

	gr_event_push(NEXTHOP_EVENT_NEW, nh);

	return nh;
}

struct pool_iterator {
	struct nh_pool *nhp;
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

void nh_pool_iter(struct nh_pool *nhp, nh_iter_cb_t nh_cb, void *priv) {
	struct pool_iterator it = {
		.nhp = nhp,
		.user_cb = nh_cb,
		.priv = priv,
	};
	rte_mempool_obj_iter(nhp->mp, nh_pool_iter_cb, &it);
}

struct lookup_filter {
	uint16_t vrf_id;
	uint16_t iface_id;
	uint8_t family;
	const void *addr;
	struct nexthop *nh;
};

static void nh_lookup_cb(struct nexthop *nh, void *priv) {
	struct lookup_filter *filter = priv;

	if (filter->nh != NULL || nh->vrf_id != filter->vrf_id)
		return;

	switch (filter->family) {
	case AF_INET:
		if (nh->ipv4 == *(ip4_addr_t *)filter->addr)
			filter->nh = nh;
		break;
	case AF_INET6:
		if (rte_ipv6_addr_eq(&nh->ipv6, filter->addr)) {
			bool is_linklocal = rte_ipv6_addr_is_linklocal(&nh->ipv6);
			if (!is_linklocal || nh->iface_id == filter->iface_id)
				filter->nh = nh;
		}
		break;
	}
}

struct nexthop *
nexthop_lookup(struct nh_pool *nhp, uint16_t vrf_id, uint16_t iface_id, const void *addr) {
	struct lookup_filter filter = {
		.family = nhp->family, .vrf_id = vrf_id, .iface_id = iface_id, .addr = addr
	};
	nh_pool_iter(nhp, nh_lookup_cb, &filter);
	return filter.nh ?: errno_set_null(ENOENT);
}

void nexthop_decref(struct nexthop *nh) {
	if (nh->ref_count <= 1) {
		struct rte_mempool *pool = nh->pool->mp;
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

static void nexthop_ageing_cb(struct nexthop *nh, void *priv) {
	clock_t now = gr_clock_us();
	time_t reply_age, request_age;
	unsigned probes, max_probes;
	struct nh_pool *nhp = priv;

	if (nh->flags & GR_NH_F_STATIC)
		return;

	reply_age = (now - nh->last_reply) / CLOCKS_PER_SEC;
	request_age = (now - nh->last_request) / CLOCKS_PER_SEC;
	max_probes = NH_UCAST_PROBES + NH_BCAST_PROBES;
	probes = nh->ucast_probes + nh->bcast_probes;

	if (nh->flags & (GR_NH_F_PENDING | GR_NH_F_STALE) && request_age > probes) {
		if (probes >= max_probes && !(nh->flags & GR_NH_F_GATEWAY)) {
			LOG(DEBUG,
			    ADDR_F " vrf=%u failed_probes=%u held_pkts=%u: %s -> failed",
			    ADDR_W(nh->family),
			    &nh->addr,
			    nh->vrf_id,
			    probes,
			    nh->held_pkts_num,
			    gr_nh_flag_name(nh->flags & (GR_NH_F_PENDING | GR_NH_F_STALE)));

			nh->flags &= ~(GR_NH_F_PENDING | GR_NH_F_STALE);
			nh->flags |= GR_NH_F_FAILED;
		} else {
			if (nhp->solicit_nh(nh) < 0)
				LOG(ERR,
				    ADDR_F " vrf=%u solicit failed: %s",
				    ADDR_W(nh->family),
				    &nh->addr,
				    nh->vrf_id,
				    strerror(errno));
		}
	} else if (nh->flags & GR_NH_F_REACHABLE && reply_age > NH_LIFETIME_REACHABLE) {
		nh->flags &= ~GR_NH_F_REACHABLE;
		nh->flags |= GR_NH_F_STALE;
	} else if (nh->flags & GR_NH_F_FAILED && request_age > NH_LIFETIME_UNREACHABLE) {
		LOG(DEBUG,
		    ADDR_F " vrf=%u failed_probes=%u held_pkts=%u: failed -> <destroy>",
		    ADDR_W(nh->family),
		    &nh->addr,
		    nh->vrf_id,
		    probes,
		    nh->held_pkts_num);
		nhp->free_nh(nh);
	}
}

static void nh_pool_do_ageing(evutil_socket_t, short /*what*/, void *priv) {
	struct nh_pool *nhp = priv;
	nh_pool_iter(nhp, nexthop_ageing_cb, nhp);
}

int nexthop_serialize(const void *obj, void **buf) {
	struct gr_nexthop *api_nh = calloc(1, sizeof(*api_nh));
	const struct nexthop *nh = obj;

	if (api_nh == NULL)
		return errno_set(ENOMEM);

	api_nh->family = nh->family;
	api_nh->vrf_id = nh->vrf_id;
	api_nh->iface_id = nh->iface_id;
	api_nh->ipv6 = nh->ipv6;
	api_nh->mac = nh->lladdr;
	api_nh->prefixlen = nh->prefixlen;
	*buf = api_nh;

	return sizeof(*api_nh);
}

static struct gr_event_serializer nh_serializer = {
	.callback = nexthop_serialize,
	.ev_count = 3,
	.ev_types = {
		NEXTHOP_EVENT_NEW,
		NEXTHOP_EVENT_DELETE,
		NEXTHOP_EVENT_UPDATE,
	},
};

RTE_INIT(init) {
	gr_event_register_serializer(&nh_serializer);
}
