// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_clock.h>
#include <gr_event.h>
#include <gr_id_pool.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_module.h>
#include <gr_nh_control.h>
#include <gr_rcu.h>
#include <gr_vec.h>

#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_telemetry.h>

#include <stdint.h>

#define DEFAULT_MAX_COUNT (1 << 17)
#define DEFAULT_MAX_HELD_PKTS 256
#define DEFAULT_LIFETIME_REACHABLE (20 * 60)
#define DEFAULT_LIFETIME_UNREACHABLE 60
#define DEFAULT_UCAST_PROBES 3
#define DEFAULT_BCAST_PROBES 3

static struct rte_mempool *pool;
static struct gr_id_pool *pool_id;
static struct rte_hash *hash_by_addr;
static struct rte_hash *hash_by_id;
static struct event *ageing_timer;
static const struct nexthop_af_ops *af_ops[256];
static const struct nexthop_type_ops *type_ops[256];
static struct nh_stats nh_stats;

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

static struct gr_id_pool *create_idpool(const struct gr_nexthop_config *c) {
	if (pool_id != NULL && gr_id_pool_used(pool_id))
		return errno_set_null(EBUSY);

	struct gr_id_pool *pid = gr_id_pool_create(1, c->max_count);
	if (pid == NULL)
		return errno_log_null(rte_errno, "gr_id_pool_create");

	return pid;
}

static void nexthop_id_put(struct nexthop *nh) {
	if (nh->nh_id == 0)
		return;

	if (nh->nh_id <= nh_conf.max_count)
		gr_id_pool_put(pool_id, nh->nh_id);

	rte_hash_del_key(hash_by_id, &nh->nh_id);
	nh->nh_id = 0;
	return;
}

static int nexthop_id_get(struct nexthop *nh) {
	int ret;

	// no id for internal, as we should not let user manipulate it
	if (nh->origin == GR_NH_ORIGIN_INTERNAL) {
		nh->nh_id = 0;
		return 0;
	}
	// don't allocate nh id for address, else will conflict with zebra nexthop address
	if (nh->nh_id == 0 && nh->origin == GR_NH_ORIGIN_LINK)
		return 0;

	// if no id allocate one
	if (nh->nh_id == 0) {
		nh->nh_id = gr_id_pool_get(pool_id);
		if (nh->nh_id == 0)
			return errno_set(ENOSPC);
		// book id if this one in the range of id allocated
		// (user is allowed to use id outside > max_count
	} else if (nh->nh_id <= nh_conf.max_count && gr_id_pool_book(pool_id, nh->nh_id) < 0)
		return errno_set(EBUSY);

	ret = rte_hash_add_key_data(hash_by_id, &nh->nh_id, nh);
	if (ret < 0) {
		if (nh->nh_id <= nh_conf.max_count)
			gr_id_pool_put(pool_id, nh->nh_id);
		return errno_set(-ret);
	}
	return 0;
}

struct nexthop_key {
	addr_family_t af;
	uint16_t vrf_id;
	union {
		ip4_addr_t ipv4;
		struct rte_ipv6_addr ipv6;
	};
};

static inline void set_nexthop_key(
	struct nexthop_key *key,
	addr_family_t af,
	uint16_t vrf_id,
	uint16_t iface_id,
	const void *addr
) {
	memset(key, 0, sizeof(*key));
	key->af = af;
	key->vrf_id = vrf_id;
	switch (af) {
	case GR_AF_IP4:
		key->ipv4 = *(ip4_addr_t *)addr;
		break;
	case GR_AF_IP6:
		key->ipv6 = *(struct rte_ipv6_addr *)addr;
		if (rte_ipv6_addr_is_linklocal(&key->ipv6)) {
			key->ipv6.a[2] = (iface_id >> 8) & 0xff;
			key->ipv6.a[3] = iface_id & 0xff;
		}
		break;
	case GR_AF_UNSPEC:
		ABORT("AF_UNSPEC has no nexthop key with gw");
		break;
	}
}

static struct rte_hash *create_hash_by_addr(const struct gr_nexthop_config *c) {
	if (hash_by_addr != NULL && rte_hash_count(hash_by_addr) > 0)
		return errno_set_null(EBUSY);

	struct rte_hash_parameters params = {
		.name = "nexthop-addrs",
		.socket_id = SOCKET_ID_ANY,
		.key_len = sizeof(struct nexthop_key),
		.entries = c->max_count,
	};

	struct rte_hash *h = rte_hash_create(&params);
	if (h == NULL)
		return errno_log_null(rte_errno, "rte_hash_create");

	struct rte_hash_rcu_config conf = {
		.v = gr_datapath_rcu(),
		.mode = RTE_HASH_QSBR_MODE_SYNC,
	};
	if (rte_hash_rcu_qsbr_add(h, &conf)) {
		rte_hash_free(h);
		return errno_log_null(rte_errno, "rte_hash_rcu_qsbr_add");
	}

	return h;
}

static struct rte_hash *create_hash_by_id(const struct gr_nexthop_config *c) {
	if (hash_by_id != NULL && rte_hash_count(hash_by_id) > 0)
		return errno_set_null(EBUSY);

	struct rte_hash_parameters params = {
		.name = "nexthop-ids",
		.socket_id = SOCKET_ID_ANY,
		.key_len = sizeof(uint32_t),
		.entries = c->max_count,
	};

	struct rte_hash *h = rte_hash_create(&params);
	if (h == NULL)
		return errno_log_null(rte_errno, "rte_hash_create");

	struct rte_hash_rcu_config conf = {
		.v = gr_datapath_rcu(),
		.mode = RTE_HASH_QSBR_MODE_SYNC,
	};
	if (rte_hash_rcu_qsbr_add(h, &conf)) {
		rte_hash_free(h);
		return errno_log_null(rte_errno, "rte_hash_rcu_qsbr_add");
	}

	return h;
}

static int nexthop_config_allocate(const struct gr_nexthop_config *c) {
	struct rte_mempool *p = NULL;
	struct rte_hash *haddr = NULL;
	struct rte_hash *hid = NULL;
	struct gr_id_pool *pid = NULL;

	if (c->max_count == 0 || c->max_count == nh_conf.max_count)
		return 0;

	p = create_mempool(c);
	if (p == NULL)
		goto fail;

	haddr = create_hash_by_addr(c);
	if (haddr == NULL)
		goto fail;

	hid = create_hash_by_id(c);
	if (hid == NULL)
		goto fail;

	pid = create_idpool(c);
	if (pid == NULL)
		goto fail;

	rte_mempool_free(pool);
	pool = p;
	rte_hash_free(hash_by_addr);
	hash_by_addr = haddr;
	rte_hash_free(hash_by_id);
	hash_by_id = hid;
	gr_id_pool_destroy(pool_id);
	pool_id = pid;

	nh_conf.max_count = c->max_count;
	return 0;

fail:
	if (p)
		rte_mempool_free(p);
	if (haddr)
		rte_hash_free(haddr);
	if (hid)
		rte_hash_free(hid);
	if (pid)
		gr_id_pool_destroy(pid);

	return -errno;
}

int nexthop_config_set(const struct gr_nexthop_config *c) {
	nexthop_config_allocate(c);

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
	case GR_AF_UNSPEC:
	case GR_AF_IP4:
	case GR_AF_IP6:
		if (ops == NULL || ops->cleanup_routes == NULL || ops->solicit == NULL)
			ABORT("invalid af ops");
		if (af_ops[af] != NULL)
			ABORT("duplicate af ops %hhu", af);
		af_ops[af] = ops;
		return;
	}
	ABORT("invalid nexthop family %hhu", af);
}

void nexthop_type_ops_register(gr_nh_type_t type, const struct nexthop_type_ops *ops) {
	switch (type) {
	case GR_NH_T_L3:
	case GR_NH_T_SR6_OUTPUT:
	case GR_NH_T_SR6_LOCAL:
	case GR_NH_T_DNAT:
	case GR_NH_T_BLACKHOLE:
	case GR_NH_T_REJECT:
	case GR_NH_T_GROUP:
		if (ops == NULL)
			ABORT("invalid type ops");
		if (type_ops[type] != NULL)
			ABORT("duplicate type ops %hhu", type);
		type_ops[type] = ops;
		return;
	}
	ABORT("invalid nexthop type %hhu", type);
}

struct nexthop *nexthop_new(const struct gr_nexthop_base *base, const void *info) {
	struct nexthop *nh = NULL;
	void *data;
	int ret;

	switch (base->type) {
	case GR_NH_T_L3:
	case GR_NH_T_SR6_OUTPUT:
	case GR_NH_T_SR6_LOCAL:
	case GR_NH_T_DNAT:
	case GR_NH_T_BLACKHOLE:
	case GR_NH_T_REJECT:
	case GR_NH_T_GROUP:
		break;
	default:
		ABORT("invalid nexthop type %hhu", base->type);
	}

	if (rte_lcore_has_role(rte_lcore_id(), ROLE_NON_EAL))
		ABORT("nexthop created from datapath thread");

	if ((ret = rte_mempool_get(pool, &data)) < 0)
		return errno_set_null(-ret);

	nh = data;
	memset(nh, 0, sizeof(*nh));

	if ((ret = nexthop_update(nh, base, info)) < 0) {
		rte_mempool_put(pool, nh);
		return errno_set_null(-ret);
	}

	nh_stats.total++;
	nh_stats.by_type[nh->type]++;

	if (nh->origin != GR_NH_ORIGIN_INTERNAL)
		gr_event_push(GR_EVENT_NEXTHOP_NEW, nh);

	return nh;
}

int nexthop_update(struct nexthop *nh, const struct gr_nexthop_base *base, const void *info) {
	const struct nexthop_type_ops *ops = type_ops[base->type];
	int ret;

	nexthop_id_put(nh);

	if (nh->ref_count > 0 && base->type != nh->type) {
		assert(nh_stats.by_type[nh->type] > 0);
		nh_stats.by_type[nh->type]--;
		nh_stats.by_type[base->type]++;
	}

	// Copy base fields
	nh->base = *base;

	if ((ret = nexthop_id_get(nh)) < 0)
		return ret;

	if (nh->iface_id != GR_IFACE_ID_UNDEF) {
		const struct iface *iface = iface_from_id(nh->iface_id);
		if (iface == NULL) {
			ret = -errno;
			goto err;
		}
		nh->vrf_id = iface->vrf_id;
	} else if (get_vrf_iface(nh->vrf_id) == NULL) {
		ret = -errno;
		goto err;
	}

	// Import type-specific info using callback
	if (ops != NULL && ops->import_info != NULL) {
		if ((ret = ops->import_info(nh, info)) < 0)
			goto err;
	}

	if (nh->ref_count > 0 && nh->origin != GR_NH_ORIGIN_INTERNAL)
		gr_event_push(GR_EVENT_NEXTHOP_UPDATE, nh);

	return 0;

err:
	nexthop_id_put(nh);
	return ret;
}

struct gr_nexthop *nexthop_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_type_ops *ops = type_ops[nh->type];

	if (ops != NULL && ops->to_api != NULL)
		return ops->to_api(nh, len);

	struct gr_nexthop *pub = malloc(sizeof(*pub));
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	*len = sizeof(*pub);

	return pub;
}

bool nexthop_equal(const struct nexthop *a, const struct nexthop *b) {
	const struct nexthop_type_ops *ops = type_ops[a->type];

	if (a->vrf_id != b->vrf_id || a->iface_id != b->iface_id || a->type != b->type)
		return false;

	if (ops != NULL && ops->equal != NULL)
		if (!ops->equal(a, b))
			return false;

	return true;
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

struct nexthop *
nexthop_lookup(addr_family_t af, uint16_t vrf_id, uint16_t iface_id, const void *addr) {
	struct nexthop_key key;
	void *data;

	if (af == AF_UNSPEC)
		return NULL;

	set_nexthop_key(&key, af, vrf_id, iface_id, addr);

	if (rte_hash_lookup_data(hash_by_addr, &key, &data) < 0)
		return errno_set_null(ENOENT);

	return data;
}

struct nexthop *nexthop_lookup_by_id(uint32_t nh_id) {
	void *data;

	if (rte_hash_lookup_data(hash_by_id, &nh_id, &data) < 0)
		return errno_set_null(ENOENT);

	return data;
}

static void nh_groups_remove_member(const struct nexthop *nh) {
	struct nexthop_info_group *info;
	struct nexthop *group;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(hash_by_id, &key, &data, &next) >= 0) {
		group = data;
		if (group->type != GR_NH_T_GROUP)
			continue;
		info = nexthop_info_group(group);
		for (uint32_t i = 0; i < info->n_members; i++) {
			if (info->members[i].nh == nh) {
				info->members[i].nh = info->members[info->n_members - 1].nh;
				info->members[i].weight = info->members[info->n_members - 1].weight;
				info->n_members--;
			}
		}
	}
}

void nexthop_routes_cleanup(struct nexthop *nh) {
	const struct nexthop_af_ops *ops;
	for (unsigned i = 0; i < ARRAY_DIM(af_ops); i++) {
		ops = af_ops[i];
		if (ops != NULL)
			ops->cleanup_routes(nh);
	}
}

static void nh_cleanup_interface_cb(struct nexthop *nh, void *priv) {
	struct lookup_filter *filter = priv;
	if (nh->iface_id == filter->iface_id) {
		nexthop_routes_cleanup(nh);
		while (nh->ref_count)
			nexthop_decref(nh);
	}
}

void nexthop_iface_cleanup(uint16_t iface_id) {
	struct lookup_filter filter = {.iface_id = iface_id};
	nexthop_iter(nh_cleanup_interface_cb, &filter);
}

void nexthop_destroy(struct nexthop *nh) {
	assert(nh->ref_count == 0);

	nh_groups_remove_member(nh);
	nexthop_id_put(nh);
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);

	// Push NEXTHOP_DELETE event after RCU sync to ensure all datapath
	// threads have seen that this nexthop is gone. At this point, only
	// packets already in the control output ring may still reference it.
	// The event triggers a drain that frees those packets before we free
	// the nexthop memory.
	if (nh->origin != GR_NH_ORIGIN_INTERNAL)
		gr_event_push(GR_EVENT_NEXTHOP_DELETE, nh);

	assert(nh_stats.total > 0);
	nh_stats.total--;
	assert(nh_stats.by_type[nh->type] > 0);
	nh_stats.by_type[nh->type]--;

	const struct nexthop_type_ops *ops = type_ops[nh->type];
	if (ops != NULL && ops->free != NULL)
		ops->free(nh);
	rte_mempool_put(pool, nh);
}

void nexthop_decref(struct nexthop *nh) {
	assert(nh->ref_count > 0);
	nh->ref_count--;
	if (nh->ref_count == 0)
		nexthop_destroy(nh);
}

void nexthop_incref(struct nexthop *nh) {
	nh->ref_count++;
}

static void nexthop_ageing_cb(struct nexthop *nh, void *) {
	const struct nexthop_af_ops *ops;
	clock_t now = gr_clock_us();
	unsigned probes, max_probes;
	struct nexthop_info_l3 *l3;
	time_t reply_age;

	if (nh->type != GR_NH_T_L3)
		return;

	l3 = nexthop_info_l3(nh);

	if (l3->flags & GR_NH_F_STATIC)
		return;

	ops = af_ops[l3->af];
	reply_age = (now - l3->last_reply) / CLOCKS_PER_SEC;
	max_probes = nh_conf.max_ucast_probes + nh_conf.max_bcast_probes;
	probes = l3->ucast_probes + l3->bcast_probes;

	switch (l3->state) {
	case GR_NH_S_NEW:
		break;
	case GR_NH_S_PENDING:
	case GR_NH_S_STALE:
		if (probes >= max_probes) {
			LOG(DEBUG,
			    ADDR_F " vrf=%u failed_probes=%u held_pkts=%u: %s -> failed",
			    ADDR_W(l3->af),
			    &l3->addr,
			    nh->vrf_id,
			    probes,
			    l3->held_pkts,
			    gr_nh_state_name(l3->state));

			l3->state = GR_NH_S_FAILED;
		} else {
			if (ops->solicit(nh) < 0)
				LOG(ERR,
				    ADDR_F " vrf=%u solicit failed: %s",
				    ADDR_W(l3->af),
				    &l3->addr,
				    nh->vrf_id,
				    strerror(errno));
		}
		break;
	case GR_NH_S_REACHABLE:
		if (reply_age > nh_conf.lifetime_reachable_sec) {
			l3->state = GR_NH_S_STALE;
		}
		break;
	case GR_NH_S_FAILED:
		break;
	}
}

static void do_ageing(evutil_socket_t, short /*what*/, void * /*priv*/) {
	nexthop_iter(nexthop_ageing_cb, NULL);
}

const struct nh_stats *nexthop_get_stats(void) {
	return &nh_stats;
}

static void nh_init(struct event_base *ev_base) {
	pool = create_mempool(&nh_conf);
	if (pool == NULL)
		ABORT("rte_mempool_create(nexthops) failed");

	hash_by_addr = create_hash_by_addr(&nh_conf);
	if (hash_by_addr == NULL)
		ABORT("rte_hash_create(nexthop-addrs) failed");

	hash_by_id = create_hash_by_id(&nh_conf);
	if (hash_by_id == NULL)
		ABORT("rte_hash_create(nexthop-ids) failed");

	pool_id = create_idpool(&nh_conf);
	if (pool_id == NULL)
		ABORT("gr_id_pool_create(nexthop-ids) failed");

	ageing_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, do_ageing, NULL);
	if (ageing_timer == NULL)
		ABORT("event_new() failed");

	if (event_add(ageing_timer, &(struct timeval) {.tv_sec = 1}) < 0)
		ABORT("event_add() failed");
}

static void nh_fini(struct event_base *) {
	rte_hash_free(hash_by_addr);
	rte_hash_free(hash_by_id);
	if (ageing_timer)
		event_free(ageing_timer);
	rte_mempool_free(pool);
}

int nexthop_serialize(const void *obj, void **buf) {
	struct gr_nexthop *nh;
	size_t len = 0;

	nh = nexthop_to_api(obj, &len);
	if (nh == NULL)
		return -errno;

	*buf = nh;

	return len;
}

static struct gr_event_serializer nh_serializer = {
	.callback = nexthop_serialize,
	.ev_count = 3,
	.ev_types = {
		GR_EVENT_NEXTHOP_NEW,
		GR_EVENT_NEXTHOP_DELETE,
		GR_EVENT_NEXTHOP_UPDATE,
	},
};

static struct gr_module module = {
	.name = "nexthop",
	.depends_on = "rcu,control_output",
	.init = nh_init,
	.fini = nh_fini,
};

static int
telemetry_nexthop_stats_get(const char * /*cmd*/, const char * /*params*/, struct rte_tel_data *d) {
	rte_tel_data_start_dict(d);

	rte_tel_data_add_dict_uint(d, "total", nh_stats.total);
	for (unsigned t = 0; t < ARRAY_DIM(nh_stats.by_type); t++) {
		if (nh_stats.by_type[t] > 0)
			rte_tel_data_add_dict_uint(d, gr_nh_type_name(t), nh_stats.by_type[t]);
	}

	return 0;
}

static void l3_free(struct nexthop *nh) {
	struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);

	if (l3->ipv4 != 0 || !rte_ipv6_addr_is_unspec(&l3->ipv6)) {
		struct nexthop_key key;
		set_nexthop_key(&key, l3->af, nh->vrf_id, nh->iface_id, &l3->addr);
		rte_hash_del_key(hash_by_addr, &key);
	}

	// Flush all held packets.
	struct rte_mbuf *m = l3->held_pkts_head;
	while (m != NULL) {
		struct rte_mbuf *next = queue_mbuf_data(m)->next;
		rte_pktmbuf_free(m);
		m = next;
	}
}

static bool l3_equal(const struct nexthop *a, const struct nexthop *b) {
	const struct nexthop_info_l3 *l3_a = nexthop_info_l3(a);
	const struct nexthop_info_l3 *l3_b = nexthop_info_l3(b);

	if (l3_a->af != l3_b->af || l3_a->prefixlen != l3_b->prefixlen)
		return false;

	switch (l3_a->af) {
	case GR_AF_IP4:
		return l3_a->ipv4 == l3_b->ipv4;
	case GR_AF_IP6:
		return rte_ipv6_addr_eq(&l3_a->ipv6, &l3_b->ipv6);
	case GR_AF_UNSPEC:
		return true;
	}
	return false;
}

static int l3_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_l3 priv = *nexthop_info_l3(nh);
	const struct gr_nexthop_info_l3 *pub = info;
	struct nexthop_key key;
	int ret;

	priv.flags = pub->flags;

	switch (pub->af) {
	case GR_AF_IP4:
		if (pub->ipv4 == 0)
			return errno_set(EDESTADDRREQ);
		break;
	case GR_AF_IP6:
		if (rte_ipv6_addr_is_unspec(&pub->ipv6))
			return errno_set(EDESTADDRREQ);

		break;
	case GR_AF_UNSPEC:
		if (pub->ipv4 || !rte_ipv6_addr_is_unspec(&pub->ipv6))
			return errno_set(EINVAL);

		priv.flags |= GR_NH_F_LINK | GR_NH_F_STATIC;
		break;
	default:
		return errno_set(ENOPROTOOPT);
	}

	if (!rte_is_zero_ether_addr(&pub->mac)) {
		if (pub->af == GR_AF_UNSPEC)
			return errno_set(EINVAL);

		priv.mac = pub->mac;
		priv.state = GR_NH_S_REACHABLE;
		priv.flags |= GR_NH_F_STATIC;
	}

	if (priv.ipv4 != 0 || !rte_ipv6_addr_is_unspec(&priv.ipv6)) {
		// Free old entry in the hash table.
		set_nexthop_key(&key, priv.af, nh->vrf_id, nh->iface_id, &priv.addr);
		rte_hash_del_key(hash_by_addr, &key);
	}

	// Copy new fields in the private info section.
	priv.ipv6 = pub->ipv6; // ipv6 encompasses ipv4
	priv.af = pub->af;
	priv.prefixlen = pub->prefixlen;

	if (priv.ipv4 != 0 || !rte_ipv6_addr_is_unspec(&priv.ipv6)) {
		// Add new entry in hash table for fast lookup.
		set_nexthop_key(&key, priv.af, nh->vrf_id, nh->iface_id, &priv.addr);
		if ((ret = rte_hash_add_key_data(hash_by_addr, &key, nh)) < 0)
			return errno_set(-ret);
	}

	*nexthop_info_l3(nh) = priv;

	return 0;
}

static struct gr_nexthop *l3_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_l3 *l3_priv = nexthop_info_l3(nh);
	struct gr_nexthop_info_l3 *l3_pub;
	struct gr_nexthop *pub;

	pub = malloc(sizeof(*pub) + sizeof(*l3_pub));
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	l3_pub = (struct gr_nexthop_info_l3 *)pub->info;
	*l3_pub = l3_priv->base;

	*len = sizeof(*pub) + sizeof(*l3_pub);

	return pub;
}

static struct nexthop_type_ops l3_nh_ops = {
	.free = l3_free,
	.equal = l3_equal,
	.import_info = l3_import_info,
	.to_api = l3_to_api,
};

static bool group_equal(const struct nexthop *a, const struct nexthop *b) {
	const struct nexthop_info_group *da = nexthop_info_group(a);
	const struct nexthop_info_group *db = nexthop_info_group(b);

	if (da->n_members != db->n_members)
		return false;
	for (uint32_t i = 0; i < da->n_members; i++)
		if (da->members[i].nh != db->members[i].nh
		    || da->members[i].weight != db->members[i].weight)
			return false;
	return true;
}

static void group_free(struct nexthop *nh) {
	struct nexthop_info_group *pvt = nexthop_info_group(nh);

	for (uint32_t i = 0; i < pvt->n_members; i++)
		nexthop_decref(pvt->members[i].nh);
	rte_free(pvt->members);
	rte_free(pvt->reta);
}

static int order_by_weight_desc(const void *a, const void *b) {
	const struct nh_group_member *ma = a;
	const struct nh_group_member *mb = b;
	return mb->weight - ma->weight;
}

static int group_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_group *pvt = nexthop_info_group(nh);
	const struct gr_nexthop_info_group *group = info;
	struct nh_group_member *members = NULL;
	struct nh_group_member *tmp = NULL;
	struct nexthop **old_reta = NULL;
	uint32_t min_weight, max_weight;
	struct nexthop **reta = NULL;
	uint32_t reta_size = 0;
	uint32_t n_tmp = 0;

	members = rte_zmalloc(
		__func__, group->n_members * sizeof(pvt->members[0]), RTE_CACHE_LINE_SIZE
	);
	if (group->n_members > 0 && members == NULL) {
		errno_set(ENOMEM);
		goto cleanup;
	}

	for (uint16_t i = 0; i < group->n_members; i++) {
		struct nexthop *nh = nexthop_lookup_by_id(group->members[i].nh_id);
		if (nh) {
			members[i].nh = nh;
			members[i].weight = group->members[i].weight;
		} else {
			errno = ENOENT;
			goto cleanup;
		}
	}

	if (group->n_members > 0) {
		// Order by desc weight: if we have too many nh in the nhg, the ones with
		// a higher weight will be included.
		qsort(members, group->n_members, sizeof(members[0]), order_by_weight_desc);

		max_weight = members[0].weight;
		min_weight = members[group->n_members - 1].weight;
		if (min_weight == 0)
			min_weight = 1;

		reta_size = (max_weight / min_weight) * group->n_members;
		if (reta_size > MAX_NH_GROUP_RETA_SIZE) {
			LOG(WARNING,
			    "nhg(%u) reta overflow (%u > %u)",
			    nh->nh_id,
			    reta_size,
			    MAX_NH_GROUP_RETA_SIZE);
			reta_size = MAX_NH_GROUP_RETA_SIZE;
		}
		reta_size = rte_align32pow2(reta_size);

		reta = rte_zmalloc(__func__, reta_size * sizeof(*reta), RTE_CACHE_LINE_SIZE);
		if (reta == NULL) {
			errno = ENOMEM;
			goto cleanup;
		}

		for (uint16_t i = 0; i < group->n_members; i++)
			nexthop_incref(members[i].nh);

		// Fill the reta table with weighted distribution
		uint32_t total_weight = 0;
		for (uint16_t i = 0; i < group->n_members; i++)
			total_weight += members[i].weight;

		if (total_weight > 0) {
			uint32_t reta_idx = 0;
			uint32_t entries;

			for (uint16_t i = 0; i < group->n_members && reta_idx < reta_size; i++) {
				entries = (members[i].weight * reta_size + total_weight / 2)
					/ total_weight;

				if (entries == 0 && members[i].weight > 0)
					entries = 1;

				for (uint16_t j = 0; j < entries && reta_idx < reta_size; j++)
					reta[reta_idx++] = members[i].nh;
			}

			// Fill remaining entries with the first member if any slots left
			while (reta_idx < reta_size && group->n_members > 0)
				reta[reta_idx++] = members[0].nh;
		}
	}

	n_tmp = pvt->n_members;
	tmp = pvt->members;
	old_reta = pvt->reta;
	pvt->n_members = group->n_members;
	pvt->members = members;
	pvt->reta_size = reta_size;
	pvt->reta = reta;

	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);

	for (uint32_t i = 0; i < n_tmp; i++)
		nexthop_decref(tmp[i].nh);

	rte_free(old_reta);
	rte_free(tmp);
	return 0;

cleanup:
	rte_free(tmp);
	rte_free(reta);
	rte_free(members);
	return errno_set(errno);
}

static struct gr_nexthop *group_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_group *group_priv = nexthop_info_group(nh);
	struct gr_nexthop_info_group *group_pub;
	struct gr_nexthop *pub;
	*len = sizeof(*pub) + sizeof(*group_pub)
		+ group_priv->n_members * sizeof(group_priv->members[0]);

	pub = malloc(*len);
	if (pub == NULL) {
		*len = 0;
		return errno_set_null(ENOMEM);
	}

	pub->base = nh->base;
	group_pub = (struct gr_nexthop_info_group *)pub->info;

	group_pub->n_members = group_priv->n_members;
	for (uint32_t i = 0; i < group_pub->n_members; i++) {
		group_pub->members[i].nh_id = group_priv->members[i].nh->nh_id;
		group_pub->members[i].weight = group_priv->members[i].weight;
	}

	return pub;
}

static struct nexthop_type_ops group_nh_ops = {
	.equal = group_equal,
	.free = group_free,
	.import_info = group_import_info,
	.to_api = group_to_api,
};

RTE_INIT(init) {
	gr_event_register_serializer(&nh_serializer);
	gr_register_module(&module);
	rte_telemetry_register_cmd(
		"/grout/nexthop/stats", telemetry_nexthop_stats_get, "Get nexthop statistics"
	);
	nexthop_type_ops_register(GR_NH_T_L3, &l3_nh_ops);
	nexthop_type_ops_register(GR_NH_T_GROUP, &group_nh_ops);
}
