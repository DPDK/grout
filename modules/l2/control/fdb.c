// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "clock.h"
#include "config.h"
#include "event.h"
#include "iface.h"
#include "l2.h"
#include "log.h"
#include "module.h"
#include "rcu.h"

#include <rte_common.h>
#include <rte_hash.h>

LOG_TYPE("fdb");

struct fdb_key {
	uint16_t bridge_id;
	uint16_t vlan_id;
	struct rte_ether_addr mac;
};

struct fdb_entry {
	BASE(gr_fdb_entry);
	uint16_t prev_iface_id;
};

static unsigned fdb_max_entries;
static struct rte_hash *fdb_hash;
static struct rte_mempool *fdb_pool;

static void fdb_free_entry(void *pool, void *fdb) {
	event_push(GR_EVENT_FDB_DEL, fdb);
	rte_mempool_put(pool, fdb);
}

static int fdb_reconfig(unsigned max_entries) {
	char name[64];
	snprintf(name, sizeof(name), "fdb-%u", max_entries);

	struct rte_hash_parameters params = {
		.name = name,
		.socket_id = SOCKET_ID_ANY,
		.key_len = sizeof(struct fdb_key),
		.entries = max_entries,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};

	struct rte_hash *h = rte_hash_create(&params);
	if (h == NULL)
		return errno_log(rte_errno, "rte_hash_create");

	struct rte_mempool *p = rte_mempool_create(
		name,
		rte_align32pow2(max_entries) - 1,
		sizeof(struct fdb_entry),
		0, // cache size
		0, // priv size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		SOCKET_ID_ANY,
		0 // flags
	);
	if (p == NULL) {
		rte_hash_free(h);
		return errno_log(rte_errno, "rte_mempool_create");
	}

	struct rte_hash_rcu_config conf = {
		.v = gr_datapath_rcu(),
		.mode = RTE_HASH_QSBR_MODE_SYNC,
		.free_key_data_func = fdb_free_entry,
		.key_data_ptr = p,
	};
	if (rte_hash_rcu_qsbr_add(h, &conf) < 0) {
		rte_hash_free(h);
		rte_mempool_free(p);
		return errno_log(rte_errno, "rte_hash_rcu_qsbr_add");
	}

	struct rte_hash *tmp_h = fdb_hash;
	struct rte_mempool *tmp_p = fdb_pool;
	fdb_hash = h;
	fdb_pool = p;

	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), rte_lcore_id());

	rte_hash_free(tmp_h);
	rte_mempool_free(tmp_p);

	fdb_max_entries = max_entries;

	return 0;
}

const struct gr_fdb_entry *
fdb_lookup(uint16_t bridge_id, const struct rte_ether_addr *mac, uint16_t vlan_id) {
	const struct fdb_key key = {bridge_id, vlan_id, *mac};
	void *data;

	if (rte_hash_lookup_data(fdb_hash, &key, &data) < 0)
		return errno_set_null(ENOENT);

	return data;
}

// Learn a new FDB entry or refresh its last_seen timestamp.
void fdb_learn(
	uint16_t bridge_id,
	uint16_t iface_id,
	const struct rte_ether_addr *mac,
	uint16_t vlan_id,
	const struct l3_addr *vtep
) {
	const struct fdb_key key = {bridge_id, vlan_id, *mac};
	gr_clock_ns_t now = clock_ns();
	struct fdb_entry *fdb;
	void *data;

	if (rte_hash_lookup_data(fdb_hash, &key, &data) < 0) {
		if (rte_mempool_get(fdb_pool, &data) < 0)
			return; // pool exhausted

		fdb = data;
		fdb->prev_iface_id = GR_IFACE_ID_UNDEF;
		fdb->bridge_id = bridge_id;
		fdb->vlan_id = vlan_id;
		fdb->mac = *mac;
		fdb->flags = GR_FDB_F_LEARN;
		fdb->iface_id = iface_id;
		fdb->vtep = *vtep;
		fdb->last_seen = now;

		if (rte_hash_add_key_data(fdb_hash, &key, fdb) < 0) {
			// no space left in hash
			rte_mempool_put(fdb_pool, fdb);
			return;
		}

		event_push(GR_EVENT_FDB_ADD, fdb);
	} else {
		fdb = data;
	}

	if ((fdb->flags & GR_FDB_F_LEARN)
	    && unlikely(fdb->iface_id != iface_id || !l3_addr_eq(&fdb->vtep, vtep))) {
		// update in case the mac address has moved
		fdb->prev_iface_id = fdb->iface_id;
		fdb->iface_id = iface_id;
		fdb->vtep = *vtep;
		event_push(GR_EVENT_FDB_UPDATE, fdb);
	}

	if (unlikely(now - fdb->last_seen > 1 * GR_NS_PER_S))
		fdb->last_seen = now;
}

void fdb_purge_iface(uint16_t iface_id) {
	struct fdb_entry *fdb;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		fdb = data;
		if (fdb->iface_id == iface_id) {
			rte_hash_del_key(fdb_hash, key);
		}
		if (fdb->prev_iface_id == iface_id) {
			fdb->prev_iface_id = GR_IFACE_ID_UNDEF;
		}
	}
}

int fdb_add_local(uint16_t bridge_id, const struct rte_ether_addr *mac) {
	const struct fdb_key key = {bridge_id, 0, *mac};
	struct fdb_entry *fdb;
	void *data;
	int ret;

	if (rte_hash_lookup_data(fdb_hash, &key, &data) >= 0)
		return errno_set(EEXIST);

	if (rte_mempool_get(fdb_pool, &data) < 0)
		return errno_set(ENOMEM);

	fdb = data;
	fdb->prev_iface_id = GR_IFACE_ID_UNDEF;
	fdb->bridge_id = bridge_id;
	fdb->vlan_id = 0;
	fdb->mac = *mac;
	fdb->flags = GR_FDB_F_LOCAL;
	fdb->iface_id = bridge_id;
	memset(&fdb->vtep, 0, sizeof(fdb->vtep));
	fdb->last_seen = gr_clock_ns();

	if ((ret = rte_hash_add_key_data(fdb_hash, &key, fdb)) < 0) {
		rte_mempool_put(fdb_pool, fdb);
		return errno_set(-ret);
	}

	event_push(GR_EVENT_FDB_ADD, fdb);

	return 0;
}

int fdb_del_local(uint16_t bridge_id, const struct rte_ether_addr *mac) {
	const struct fdb_key key = {bridge_id, 0, *mac};
	struct fdb_entry *fdb;
	void *data;

	if (rte_hash_lookup_data(fdb_hash, &key, &data) < 0)
		return errno_set(ENOENT);

	fdb = data;
	if (!(fdb->flags & GR_FDB_F_LOCAL))
		return errno_set(EPERM);

	rte_hash_del_key(fdb_hash, &key);

	return 0;
}

static struct api_out fdb_add(const void *request, struct api_ctx *) {
	const struct gr_fdb_add_req *req = request;
	const struct iface *iface;
	struct fdb_entry *e;
	void *data;
	int ret;

	if (req->fdb.flags & ~(GR_FDB_F_STATIC | GR_FDB_F_EXTERN))
		return api_out(EINVAL, 0, NULL);

	iface = iface_from_id(req->fdb.iface_id);
	if (iface == NULL)
		return api_out(errno, 0, NULL);

	iface = iface_from_id(iface->domain_id);
	if (iface == NULL)
		return api_out(EMEDIUMTYPE, 0, NULL);

	if (iface->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(EMEDIUMTYPE, 0, NULL);

	const struct fdb_key key = {iface->id, req->fdb.vlan_id, req->fdb.mac};

	if (rte_hash_lookup_data(fdb_hash, &key, &data) < 0) {
		if ((ret = rte_mempool_get(fdb_pool, &data)) < 0)
			return api_out(-ret, 0, NULL);

		e = data;
		e->prev_iface_id = GR_IFACE_ID_UNDEF;
		e->base = req->fdb;
		e->bridge_id = iface->id;
		e->last_seen = clock_ns();

		if ((ret = rte_hash_add_key_data(fdb_hash, &key, data)) < 0) {
			rte_mempool_put(fdb_pool, e);
			return api_out(-ret, 0, NULL);
		}

		event_push(GR_EVENT_FDB_ADD, e);
	} else if (req->exist_ok) {
		e = data;
		if (e->flags & GR_FDB_F_LOCAL)
			return api_out(EPERM, 0, NULL);

		e->prev_iface_id = e->iface_id;
		e->base = req->fdb;
		e->bridge_id = iface->id;
		e->last_seen = clock_ns();

		event_push(GR_EVENT_FDB_UPDATE, e);
	} else {
		return api_out(EEXIST, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct api_out fdb_del(const void *request, struct api_ctx *) {
	const struct gr_fdb_del_req *req = request;
	const struct fdb_key key = {req->bridge_id, req->vlan_id, req->mac};
	void *data;
	int ret;

	if (rte_hash_lookup_data(fdb_hash, &key, &data) >= 0) {
		// The bridge's own SVI MAC is managed by the bridge lifecycle.
		const struct fdb_entry *fdb = data;
		if (fdb->flags & GR_FDB_F_LOCAL)
			return api_out(EPERM, 0, NULL);
	}

	ret = rte_hash_del_key(fdb_hash, &key);
	if (ret == -ENOENT && req->missing_ok)
		ret = 0;
	else if (ret > 0)
		ret = 0;

	return api_out(-ret, 0, NULL);
}

static inline bool fdb_match(
	const struct gr_fdb_entry *e,
	gr_fdb_flags_t flags,
	uint16_t bridge_id,
	uint16_t iface_id,
	const struct rte_ether_addr *mac
) {
	if ((flags & GR_FDB_F_STATIC) && !(e->flags & GR_FDB_F_STATIC))
		return false;
	if ((flags & GR_FDB_F_LEARN) && !(e->flags & GR_FDB_F_LEARN))
		return false;
	if ((flags & GR_FDB_F_EXTERN) && !(e->flags & GR_FDB_F_EXTERN))
		return false;
	if ((flags & GR_FDB_F_LOCAL) && !(e->flags & GR_FDB_F_LOCAL))
		return false;
	if (bridge_id != GR_IFACE_ID_UNDEF && e->bridge_id != bridge_id)
		return false;
	if (iface_id != GR_IFACE_ID_UNDEF && e->iface_id != iface_id)
		return false;
	if (mac != NULL && !rte_is_zero_ether_addr(mac) && !rte_is_same_ether_addr(&e->mac, mac))
		return false;
	return true;
}

static struct api_out fdb_flush(const void *request, struct api_ctx *) {
	const struct gr_fdb_flush_req *req = request;
	uint32_t next = 0;
	const void *key;
	void *data;
	int ret;

	if (req->flags & ~(GR_FDB_F_STATIC | GR_FDB_F_LEARN))
		return api_out(EINVAL, 0, NULL);

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		if (((struct fdb_entry *)data)->flags & GR_FDB_F_LOCAL)
			continue;
		if (!fdb_match(data, req->flags, req->bridge_id, req->iface_id, &req->mac))
			continue;

		ret = rte_hash_del_key(fdb_hash, key);
		if (ret < 0)
			return api_out(-ret, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct api_out fdb_list(const void *request, struct api_ctx *ctx) {
	const struct gr_fdb_list_req *req = request;
	struct fdb_entry *fdb;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		if (!fdb_match(data, req->flags, req->bridge_id, req->iface_id, NULL))
			continue;

		fdb = data;
		api_send(ctx, sizeof(fdb->base), fdb);
	}

	return api_out(0, 0, NULL);
}

static struct api_out fdb_config_get(const void * /*request*/, struct api_ctx *) {
	struct gr_fdb_config_get_resp *resp = malloc(sizeof(*resp));

	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->max_entries = fdb_max_entries;
	resp->used_entries = rte_hash_count(fdb_hash);

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out fdb_config_set(const void *request, struct api_ctx *) {
	const struct gr_fdb_config_set_req *req = request;

	if (req->max_entries == 0)
		return api_out(EINVAL, 0, NULL);

	if (req->max_entries != fdb_max_entries) {
		if (rte_hash_count(fdb_hash) > 0)
			return api_out(EBUSY, 0, NULL);

		if (fdb_reconfig(req->max_entries) < 0)
			return api_out(errno, 0, NULL);

		fdb_max_entries = req->max_entries;
	}

	return api_out(0, 0, NULL);
}

static void push_mac_to_hw(struct iface *iface, const struct rte_ether_addr *mac, bool add) {
	int ret;

	if (add)
		ret = iface_add_eth_addr(iface, mac);
	else
		ret = iface_del_eth_addr(iface, mac);
	if (ret < 0) {
		LOG(DEBUG,
		    "failed to %s mac " ETH_F " to %s: %s",
		    add ? "add" : "del",
		    mac,
		    iface->name,
		    strerror(errno));
	}
}

static void fdb_event_cb(uint32_t event, const void *obj) {
	const struct iface_info_bridge *bridge_info;
	const struct fdb_entry *fdb = obj;
	const struct iface *bridge;
	struct iface *member;

	// The bridge may have been removed already. HW filters were cleaned up
	// in fdb_iface_del_cb before the RCU deferred free triggered this event.
	bridge = iface_from_id(fdb->bridge_id);
	if (bridge == NULL)
		return;

	// we have no clear idea what to do with a vlan_id if one got pushed by FRR
	assert(fdb->vlan_id == 0);

	if (event == GR_EVENT_FDB_UPDATE) {
		if (fdb->prev_iface_id == fdb->iface_id)
			return;

		member = iface_from_id(fdb->prev_iface_id);
		if (member != NULL)
			push_mac_to_hw(member, &fdb->mac, true);
		member = iface_from_id(fdb->iface_id);
		if (member != NULL)
			push_mac_to_hw(member, &fdb->mac, false);
		return;
	}

	bridge_info = iface_info_bridge(bridge);
	for (unsigned i = 0; i < bridge_info->n_members; i++) {
		member = bridge_info->members[i];

		// skip the interface where the MAC was learned
		if (member->id == fdb->iface_id)
			continue;

		push_mac_to_hw(member, &fdb->mac, event != GR_EVENT_FDB_DEL);
	}
}

void fdb_sync_hardware(const struct iface *bridge, struct iface *member, bool add) {
	struct fdb_entry *fdb;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		fdb = data;

		if (fdb->bridge_id != bridge->id)
			continue;
		// skip the interface where the MAC was learned
		if (member->id == fdb->iface_id)
			continue;

		// we have no clear idea what to do with a vlan_id if one got pushed by FRR
		assert(fdb->vlan_id == 0);
		push_mac_to_hw(member, &fdb->mac, add);
	}
}

// Remove HW filters before deleting FDB entries. rte_hash_del_key() triggers
// a deferred RCU free (fdb_free_entry -> fdb_event_cb) which would need
// iface_from_id() to find the bridge/member, but at this point the iface is
// already removed from the global array by iface_destroy().
static void fdb_remove_hw_filters(const struct iface *bridge, const struct fdb_entry *fdb) {
	const struct iface_info_bridge *br = iface_info_bridge(bridge);
	for (unsigned i = 0; i < br->n_members; i++) {
		if (br->members[i]->id != fdb->iface_id)
			push_mac_to_hw(br->members[i], &fdb->mac, false);
	}
}

static void fdb_iface_del_cb(uint32_t /*event*/, const void *obj) {
	const struct iface *iface = obj;
	const struct iface *bridge;
	struct fdb_entry *fdb;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		fdb = data;

		if (iface->type == GR_IFACE_TYPE_BRIDGE && fdb->bridge_id == iface->id) {
			fdb_remove_hw_filters(iface, fdb);
			rte_hash_del_key(fdb_hash, key);
		} else if (fdb->iface_id == iface->id) {
			bridge = iface_from_id(fdb->bridge_id);
			if (bridge != NULL)
				fdb_remove_hw_filters(bridge, fdb);
			rte_hash_del_key(fdb_hash, key);
		}
	}
}

static void fdb_ageing_cb(evutil_socket_t, short /*what*/, void * /*priv*/) {
	const struct iface *bridge;
	struct fdb_entry *fdb;
	gr_clock_ns_t now;
	uint32_t next = 0;
	uint16_t max_age;
	const void *key;
	void *data;
	time_t age;

	now = clock_ns();

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		fdb = data;

		if ((fdb->flags & GR_FDB_F_STATIC) || !(fdb->flags & GR_FDB_F_LEARN))
			continue;

		age = (now - fdb->last_seen) / GR_NS_PER_S;

		bridge = iface_from_id(fdb->bridge_id);
		if (bridge != NULL)
			max_age = iface_info_bridge(bridge)->ageing_time;
		else
			max_age = GR_BRIDGE_DEFAULT_AGEING;

		if (age > max_age) {
			LOG(DEBUG,
			    ETH_F " vlan=%u bridge=%u iface=%u: aged out (%ld sec)",
			    &fdb->mac,
			    fdb->vlan_id,
			    fdb->bridge_id,
			    fdb->iface_id,
			    age);
			rte_hash_del_key(fdb_hash, key);
		}
	}
}

static struct event *ageing_timer;

static void fdb_init(struct event_base *base) {
	uint32_t max = gr_config.max_fdb_entries;
	if (fdb_reconfig(max) < 0)
		ABORT("fdb_reconfig failed");

	ageing_timer = event_new(base, -1, EV_PERSIST | EV_FINALIZE, fdb_ageing_cb, NULL);
	if (ageing_timer == NULL)
		ABORT("event_new() failed");

	if (event_add(ageing_timer, &(struct timeval) {.tv_sec = 1}) < 0)
		ABORT("event_add() failed");
}

static void fdb_fini(struct event_base *) {
	if (ageing_timer != NULL)
		event_free(ageing_timer);

	rte_hash_free(fdb_hash);
	rte_mempool_free(fdb_pool);
}

static struct module module = {
	.name = "fdb",
	.depends_on = "rcu",
	.init = fdb_init,
	.fini = fdb_fini,
};

RTE_INIT(init) {
	api_handler(GR_FDB_ADD, fdb_add);
	api_handler(GR_FDB_DEL, fdb_del);
	api_handler(GR_FDB_FLUSH, fdb_flush);
	api_handler(GR_FDB_LIST, fdb_list);
	api_handler(GR_FDB_CONFIG_GET, fdb_config_get);
	api_handler(GR_FDB_CONFIG_SET, fdb_config_set);
	event_subscribe(GR_EVENT_FDB_ADD, fdb_event_cb);
	event_subscribe(GR_EVENT_FDB_DEL, fdb_event_cb);
	event_subscribe(GR_EVENT_FDB_UPDATE, fdb_event_cb);
	event_subscribe(GR_EVENT_IFACE_REMOVE, fdb_iface_del_cb);
	event_serializer(GR_EVENT_FDB_ADD, NULL);
	event_serializer(GR_EVENT_FDB_DEL, NULL);
	event_serializer(GR_EVENT_FDB_UPDATE, NULL);
	module_register(&module);
}
