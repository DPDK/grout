// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_clock.h>
#include <gr_event.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_module.h>
#include <gr_nh_control.h>
#include <gr_rcu.h>

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
static const struct nexthop_af_ops *af_ops[256];
static const struct nexthop_type_ops *type_ops[256];
struct gr_nexthop_config nh_conf = {
	.max_count = DEFAULT_MAX_COUNT,
	.lifetime_reachable_sec = DEFAULT_LIFETIME_REACHABLE,
	.lifetime_unreachable_sec = DEFAULT_LIFETIME_UNREACHABLE,
	.max_held_pkts = DEFAULT_MAX_HELD_PKTS,
	.max_ucast_probes = DEFAULT_UCAST_PROBES,
	.max_bcast_probes = DEFAULT_BCAST_PROBES,
};

static void count_nexthops(struct nexthop *, void *priv) {
	unsigned *count = priv;
	*count = *count + 1;
}

unsigned nexthop_used_count(void) {
	unsigned count = 0;
	nexthop_iter(count_nexthops, &count);
	return count;
}

static struct rte_mempool *create_mempool(const struct gr_nexthop_config *c) {
	if (pool != NULL && nexthop_used_count() > 0)
		return errno_set_null(EBUSY);

	char name[128];
	snprintf(name, sizeof(name), "nexthops-%u", c->max_count);
	struct rte_mempool *p = rte_mempool_create(
		name,
		rte_align32pow2(c->max_count) - 1,
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
	if (p == NULL)
		return errno_log_null(rte_errno, "rte_mempool_create");
	return p;
}

int nexthop_config_set(const struct gr_nexthop_config *c) {
	if (c->max_count != 0 && c->max_count != nh_conf.max_count) {
		struct rte_mempool *p = create_mempool(c);
		if (p == NULL)
			return -errno;
		rte_mempool_free(pool);
		pool = p;
		nh_conf.max_count = c->max_count;
	}
	if (c->lifetime_reachable_sec != 0)
		nh_conf.lifetime_reachable_sec = c->lifetime_reachable_sec;
	if (c->lifetime_unreachable_sec != 0)
		nh_conf.lifetime_unreachable_sec = c->lifetime_unreachable_sec;
	if (c->max_held_pkts != 0)
		nh_conf.max_held_pkts = c->max_held_pkts;
	if (c->max_ucast_probes != 0)
		nh_conf.max_ucast_probes = c->max_ucast_probes;
	if (c->max_bcast_probes != 0)
		nh_conf.max_bcast_probes = c->max_bcast_probes;

	return 0;
}

void nexthop_af_ops_register(addr_family_t af, const struct nexthop_af_ops *ops) {
	switch (af) {
	case GR_AF_IP4:
	case GR_AF_IP6:
		if (ops == NULL || ops->add == NULL || ops->del == NULL || ops->solicit == NULL)
			ABORT("invalid af ops");
		if (af_ops[af] != NULL)
			ABORT("duplicate af ops %hhu", af);
		af_ops[af] = ops;
		return;
	}
	ABORT("invalid nexthop family %hhu", af);
}

const struct nexthop_af_ops *nexthop_af_ops_get(addr_family_t af) {
	return af_ops[af];
}

void nexthop_type_ops_register(gr_nh_type_t type, const struct nexthop_type_ops *ops) {
	switch (type) {
	case GR_NH_T_L3:
	case GR_NH_T_SR6_OUTPUT:
	case GR_NH_T_SR6_LOCAL:
	case GR_NH_T_DNAT:
		if (ops == NULL || ops->free == NULL)
			ABORT("invalid type ops");
		if (type_ops[type] != NULL)
			ABORT("duplicate type ops %hhu", type);
		type_ops[type] = ops;
		return;
	}
	ABORT("invalid nexthop type %hhu", type);
}

const struct nexthop_type_ops *nexthop_type_ops_get(gr_nh_type_t type) {
	return type_ops[type];
}

struct nexthop *nexthop_new(const struct gr_nexthop *base) {
	struct nexthop *nh;
	void *data;
	int ret;

	switch (base->type) {
	case GR_NH_T_L3:
	case GR_NH_T_SR6_OUTPUT:
	case GR_NH_T_SR6_LOCAL:
	case GR_NH_T_DNAT:
		break;
	default:
		ABORT("invalid nexthop type %hhu", base->type);
	}
	switch (base->af) {
	case GR_AF_IP4:
	case GR_AF_IP6:
		break;
	default:
		ABORT("invalid nexthop family %hhu", base->af);
	}

	if (rte_lcore_has_role(rte_lcore_id(), ROLE_NON_EAL))
		ABORT("nexthop created from datapath thread");

	if ((ret = rte_mempool_get(pool, &data)) < 0)
		return errno_set_null(-ret);

	nh = data;
	nh->base = *base;

	if (nh->origin != GR_NH_ORIGIN_INTERNAL)
		gr_event_push(GR_EVENT_NEXTHOP_NEW, nh);

	return nh;
}

bool nexthop_equal(const struct nexthop *a, const struct nexthop *b) {
	if (a->vrf_id != b->vrf_id || a->iface_id != b->iface_id || a->af != b->af)
		return false;

	switch (a->af) {
	case GR_AF_IP4:
		return memcmp(&a->ipv4, &b->ipv4, sizeof(a->ipv4)) == 0;
	case GR_AF_IP6:
		return memcmp(&a->ipv6, &b->ipv6, sizeof(a->ipv6)) == 0;
	default:
		ABORT("invalid nexthop family %hhu", a->af);
	}

	return false;
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
	addr_family_t af;
	uint16_t vrf_id;
	uint16_t iface_id;
	uint32_t nh_id;
	const void *addr;
	struct nexthop *nh;
};

static void nh_lookup_cb(struct nexthop *nh, void *priv) {
	struct lookup_filter *filter = priv;

	if (filter->nh != NULL)
		return;

	if (filter->nh_id != GR_NH_ID_UNSET && filter->nh_id == nh->nh_id) {
		filter->nh = nh;
		return;
	}

	if (nh->af != filter->af || nh->vrf_id != filter->vrf_id)
		return;

	switch (filter->af) {
	case GR_AF_IP4:
		if (nh->ipv4 == *(ip4_addr_t *)filter->addr)
			filter->nh = nh;
		break;
	case GR_AF_IP6:
		if (rte_ipv6_addr_eq(&nh->ipv6, filter->addr)) {
			bool is_linklocal = rte_ipv6_addr_is_linklocal(&nh->ipv6);
			if (!is_linklocal || nh->iface_id == filter->iface_id)
				filter->nh = nh;
		}
		break;
	}
}

struct nexthop *
nexthop_lookup(addr_family_t af, uint16_t vrf_id, uint16_t iface_id, const void *addr) {
	struct lookup_filter filter = {
		.af = af, .vrf_id = vrf_id, .iface_id = iface_id, .addr = addr
	};
	nexthop_iter(nh_lookup_cb, &filter);
	return filter.nh ?: errno_set_null(ENOENT);
}

struct nexthop *nexthop_lookup_by_id(uint32_t nh_id) {
	struct lookup_filter filter = {.nh_id = nh_id};
	nexthop_iter(nh_lookup_cb, &filter);
	return filter.nh ?: errno_set_null(ENOENT);
}

static void nh_cleanup_interface_cb(struct nexthop *nh, void *priv) {
	struct lookup_filter *filter = priv;
	if (nh->iface_id == filter->iface_id) {
		while (nh->ref_count)
			nexthop_decref(nh);
	}
}

void nexthop_cleanup(uint16_t iface_id) {
	struct lookup_filter filter = {.iface_id = iface_id};
	nexthop_iter(nh_cleanup_interface_cb, &filter);
}

void nexthop_decref(struct nexthop *nh) {
	if (nh->ref_count <= 1) {
		rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);

		// Flush all held packets.
		struct rte_mbuf *m = nh->held_pkts_head;
		while (m != NULL) {
			struct rte_mbuf *next = queue_mbuf_data(m)->next;
			rte_pktmbuf_free(m);
			m = next;
		}
		if (nh->origin != GR_NH_ORIGIN_INTERNAL)
			gr_event_push(GR_EVENT_NEXTHOP_DELETE, nh);
		const struct nexthop_type_ops *ops = type_ops[nh->type];
		if (ops != NULL && ops->free != NULL)
			ops->free(nh);

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
	const struct nexthop_af_ops *ops = af_ops[nh->af];
	clock_t now = gr_clock_us();
	time_t reply_age, request_age;
	unsigned probes, max_probes;

	if (nh->flags & GR_NH_F_STATIC)
		return;

	reply_age = (now - nh->last_reply) / CLOCKS_PER_SEC;
	request_age = (now - nh->last_request) / CLOCKS_PER_SEC;
	max_probes = nh_conf.max_ucast_probes + nh_conf.max_bcast_probes;
	probes = nh->ucast_probes + nh->bcast_probes;

	switch (nh->state) {
	case GR_NH_S_NEW:
		break;
	case GR_NH_S_PENDING:
	case GR_NH_S_STALE:
		if (probes >= max_probes) {
			LOG(DEBUG,
			    ADDR_F " vrf=%u failed_probes=%u held_pkts=%u: %s -> failed",
			    ADDR_W(nh->af),
			    &nh->addr,
			    nh->vrf_id,
			    probes,
			    nh->held_pkts,
			    gr_nh_state_name(&nh->base));

			nh->state = GR_NH_S_FAILED;
		} else {
			if (ops->solicit(nh) < 0)
				LOG(ERR,
				    ADDR_F " vrf=%u solicit failed: %s",
				    ADDR_W(nh->af),
				    &nh->addr,
				    nh->vrf_id,
				    strerror(errno));
		}
		break;
	case GR_NH_S_REACHABLE:
		if (reply_age > nh_conf.lifetime_reachable_sec)
			nh->state = GR_NH_S_STALE;
		break;
	case GR_NH_S_FAILED:
		if (request_age > nh_conf.lifetime_unreachable_sec) {
			LOG(DEBUG,
			    ADDR_F " vrf=%u failed_probes=%u held_pkts=%u: failed -> <destroy>",
			    ADDR_W(nh->af),
			    &nh->addr,
			    nh->vrf_id,
			    probes,
			    nh->held_pkts);
			ops->del(nh);
		}
	}
}

static void do_ageing(evutil_socket_t, short /*what*/, void * /*priv*/) {
	nexthop_iter(nexthop_ageing_cb, NULL);
}

static void nh_init(struct event_base *ev_base) {
	pool = create_mempool(&nh_conf);
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
		GR_EVENT_NEXTHOP_NEW,
		GR_EVENT_NEXTHOP_DELETE,
		GR_EVENT_NEXTHOP_UPDATE,
	},
};

static struct gr_module module = {
	.name = "nexthop",
	.init = nh_init,
	.fini = nh_fini,
};

RTE_INIT(init) {
	gr_event_register_serializer(&nh_serializer);
	gr_register_module(&module);
}
