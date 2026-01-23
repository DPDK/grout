// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_event.h>
#include <gr_id_pool.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_metrics.h>
#include <gr_module.h>
#include <gr_nh_control.h>
#include <gr_rcu.h>
#include <gr_vec.h>

#include <rte_hash.h>
#include <rte_mempool.h>

#include <stdint.h>

#define DEFAULT_MAX_COUNT (1 << 17)
#define DEFAULT_MAX_HELD_PKTS 256
#define DEFAULT_LIFETIME_REACHABLE (20 * 60)
#define DEFAULT_LIFETIME_UNREACHABLE 60
#define DEFAULT_UCAST_PROBES 3
#define DEFAULT_BCAST_PROBES 3

static struct rte_mempool *pool;
static struct gr_id_pool *pool_id;
static struct rte_hash *hash_by_id;
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
	struct rte_hash *hid = NULL;
	struct gr_id_pool *pid = NULL;

	if (pool != NULL && (c->max_count == 0 || c->max_count == nh_conf.max_count))
		return 0;

	LOG(INFO, "%u nexthops", c->max_count);
	p = create_mempool(c);
	if (p == NULL)
		goto fail;

	hid = create_hash_by_id(c);
	if (hid == NULL)
		goto fail;

	pid = create_idpool(c);
	if (pid == NULL)
		goto fail;

	for (gr_nh_type_t t = 0; nexthop_type_valid(t); t++) {
		const struct nexthop_type_ops *ops = type_ops[t];
		if (ops == NULL || ops->reconfig == NULL)
			continue;
		LOG(INFO, "%s: %u nexthops", gr_nh_type_name(t), c->max_count);
		if (ops->reconfig(c) < 0)
			goto fail;
	}

	rte_mempool_free(pool);
	pool = p;
	rte_hash_free(hash_by_id);
	hash_by_id = hid;
	gr_id_pool_destroy(pool_id);
	pool_id = pid;

	nh_conf.max_count = c->max_count;
	return 0;

fail:
	if (p)
		rte_mempool_free(p);
	if (hid)
		rte_hash_free(hid);
	if (pid)
		gr_id_pool_destroy(pid);

	return -errno;
}

int nexthop_config_set(const struct gr_nexthop_config *c) {
	if (nexthop_config_allocate(c) < 0)
		return -errno;

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

bool nexthop_type_valid(gr_nh_type_t type) {
	switch (type) {
	case GR_NH_T_L3:
	case GR_NH_T_SR6_OUTPUT:
	case GR_NH_T_SR6_LOCAL:
	case GR_NH_T_DNAT:
	case GR_NH_T_BLACKHOLE:
	case GR_NH_T_REJECT:
	case GR_NH_T_GROUP:
		return true;
	}
	return false;
}

bool nexthop_origin_valid(gr_nh_origin_t origin) {
	switch (origin) {
	case GR_NH_ORIGIN_UNSPEC:
	case GR_NH_ORIGIN_REDIRECT:
	case GR_NH_ORIGIN_LINK:
	case GR_NH_ORIGIN_BOOT:
	case GR_NH_ORIGIN_STATIC:
	case GR_NH_ORIGIN_GATED:
	case GR_NH_ORIGIN_RA:
	case GR_NH_ORIGIN_MRT:
	case GR_NH_ORIGIN_ZEBRA:
	case GR_NH_ORIGIN_BIRD:
	case GR_NH_ORIGIN_DNROUTED:
	case GR_NH_ORIGIN_XORP:
	case GR_NH_ORIGIN_NTK:
	case GR_NH_ORIGIN_DHCP:
	case GR_NH_ORIGIN_MROUTED:
	case GR_NH_ORIGIN_KEEPALIVED:
	case GR_NH_ORIGIN_BABEL:
	case GR_NH_ORIGIN_OPENR:
	case GR_NH_ORIGIN_BGP:
	case GR_NH_ORIGIN_ISIS:
	case GR_NH_ORIGIN_OSPF:
	case GR_NH_ORIGIN_RIP:
	case GR_NH_ORIGIN_RIPNG:
	case GR_NH_ORIGIN_NHRP:
	case GR_NH_ORIGIN_EIGRP:
	case GR_NH_ORIGIN_LDP:
	case GR_NH_ORIGIN_SHARP:
	case GR_NH_ORIGIN_PBR:
	case GR_NH_ORIGIN_ZSTATIC:
	case GR_NH_ORIGIN_OPENFABRIC:
	case GR_NH_ORIGIN_SRTE:
	case GR_NH_ORIGIN_INTERNAL:
		return true;
	}
	return false;
}

void nexthop_type_ops_register(gr_nh_type_t type, const struct nexthop_type_ops *ops) {
	if (!nexthop_type_valid(type))
		ABORT("invalid type value %hhu", type);
	if (ops == NULL)
		ABORT("invalid type ops");
	if (type_ops[type] != NULL)
		ABORT("duplicate type ops %hhu", type);
	type_ops[type] = ops;
}

struct nexthop *nexthop_lookup(const struct gr_nexthop_base *base, const void *info) {
	const struct nexthop_type_ops *ops;
	struct nexthop *nh = NULL;

	if (base == NULL)
		return errno_set_null(EINVAL);

	if (base->nh_id != GR_NH_ID_UNSET)
		nh = nexthop_lookup_id(base->nh_id);

	ops = type_ops[base->type];
	if (nh == NULL && ops != NULL && ops->lookup != NULL)
		nh = ops->lookup(base, info);

	return nh;
}

struct nexthop *nexthop_new(const struct gr_nexthop_base *base, const void *info) {
	struct nexthop *nh;
	void *data;
	int ret;

	if (base == NULL)
		return errno_set_null(EINVAL);

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

	nexthop_incref(nh);

	if (nh->origin != GR_NH_ORIGIN_INTERNAL)
		gr_event_push(GR_EVENT_NEXTHOP_NEW, nh);

	return nh;
}

int nexthop_update(struct nexthop *nh, const struct gr_nexthop_base *base, const void *info) {
	const struct nexthop_type_ops *ops = type_ops[base->type];
	struct gr_nexthop_base backup = nh->base;
	int ret;

	if (!nexthop_type_valid(base->type))
		return errno_set(ESOCKTNOSUPPORT);
	if (!nexthop_origin_valid(base->origin))
		return errno_set(EPFNOSUPPORT);

	nexthop_id_put(nh);

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
	if (nh->ref_count == 0)
		nexthop_id_put(nh); // nexthop was just created, release the ID
	nh->base = backup;
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

struct nexthop *nexthop_lookup_id(uint32_t nh_id) {
	void *data;

	if (rte_hash_lookup_data(hash_by_id, &nh_id, &data) < 0)
		return errno_set_null(ENOENT);

	return data;
}

static void nh_cleanup_interface_cb(struct nexthop *nh, void *priv) {
	if (nh->iface_id == (uintptr_t)priv) {
		nexthop_routes_cleanup(nh);
		while (nh->ref_count)
			nexthop_decref(nh);
	}
}

static void nexthop_iface_cleanup(uint32_t /*ev_type*/, const void *data) {
	const struct iface *iface = data;
	nexthop_iter(nh_cleanup_interface_cb, (void *)(uintptr_t)iface->id);
}

static struct gr_event_subscription iface_subscription = {
	.callback = nexthop_iface_cleanup,
	.ev_count = 1,
	.ev_types = {GR_EVENT_IFACE_PRE_REMOVE},
};

void nexthop_destroy(struct nexthop *nh) {
	const struct nexthop_type_ops *ops;

	assert(nh->ref_count == 0);

	for (gr_nh_type_t t = 0; nexthop_type_valid(t); t++) {
		ops = type_ops[t];
		if (ops != NULL && ops->remove_references != NULL)
			ops->remove_references(nh);
	}
	nexthop_id_put(nh);

	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);

	// Push NEXTHOP_DELETE event after RCU sync to ensure all datapath
	// threads have seen that this nexthop is gone. At this point, only
	// packets already in the control queue may still reference it.
	// The event triggers a drain that frees those packets before we free
	// the nexthop memory.
	if (nh->origin != GR_NH_ORIGIN_INTERNAL)
		gr_event_push(GR_EVENT_NEXTHOP_DELETE, nh);

	ops = type_ops[nh->type];
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

static void nh_init(struct event_base *) {
	if (nexthop_config_allocate(&nh_conf) < 0)
		ABORT("nexthop_config_allocate failed: %s", strerror(errno));
}

static void nh_fini(struct event_base *) {
	rte_hash_free(hash_by_id);
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
	.depends_on = "rcu,control_queue",
	.init = nh_init,
	.fini = nh_fini,
};

METRIC_GAUGE(m_count, "nexthop_count", "Number of nexthops by type.");

static void count_types(struct nexthop *nh, void *priv) {
	uint32_t *counts = priv;
	counts[nh->type]++;
}

static void nexthop_metrics_collect(struct gr_metrics_writer *w) {
	uint32_t counts[UINT_NUM_VALUES(gr_nh_type_t)];
	struct gr_metrics_ctx ctx;

	memset(counts, 0, sizeof(counts));
	nexthop_iter(count_types, counts);

	for (gr_nh_type_t t = 0; nexthop_type_valid(t); t++) {
		gr_metrics_ctx_init(&ctx, w, "type", gr_nh_type_name(t), NULL);
		gr_metric_emit(&ctx, &m_count, counts[t]);
	}
}

static struct gr_metrics_collector nexthop_collector = {
	.name = "nexthop",
	.collect = nexthop_metrics_collect,
};

RTE_INIT(init) {
	gr_event_register_serializer(&nh_serializer);
	gr_event_subscribe(&iface_subscription);
	gr_register_module(&module);
	gr_metrics_register(&nexthop_collector);
}
