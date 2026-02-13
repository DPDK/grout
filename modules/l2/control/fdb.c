// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_clock.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_rcu.h>

#include <rte_common.h>
#include <rte_hash.h>

struct fdb_key {
	uint16_t bridge_id;
	uint16_t vlan_id;
	struct rte_ether_addr mac;
};

static unsigned fdb_max_entries;
static struct rte_hash *fdb_hash;
static struct rte_mempool *fdb_pool;

static void fdb_free_entry(void *pool, void *fdb) {
	gr_event_push(GR_EVENT_FDB_DEL, fdb);
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
		sizeof(struct gr_fdb_entry),
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
	ip4_addr_t vtep
) {
	const struct fdb_key key = {bridge_id, vlan_id, *mac};
	struct gr_fdb_entry *fdb;
	void *data;

	if (rte_hash_lookup_data(fdb_hash, &key, &data) < 0) {
		if (rte_mempool_get(fdb_pool, &data) < 0)
			return; // pool exhausted

		fdb = data;
		fdb->bridge_id = bridge_id;
		fdb->vlan_id = vlan_id;
		fdb->mac = *mac;
		fdb->flags = GR_FDB_F_LEARN;
		fdb->iface_id = iface_id;
		fdb->vtep = vtep;

		if (rte_hash_add_key_data(fdb_hash, &key, fdb) < 0) {
			// no space left in hash
			rte_mempool_put(fdb_pool, fdb);
			return;
		}

		gr_event_push(GR_EVENT_FDB_ADD, fdb);
	} else {
		fdb = data;
	}

	fdb->last_seen = gr_clock_us();

	if ((fdb->flags & GR_FDB_F_LEARN) && (fdb->iface_id != iface_id || fdb->vtep != vtep)) {
		// update in case the mac address has moved
		fdb->iface_id = iface_id;
		fdb->vtep = vtep;
		gr_event_push(GR_EVENT_FDB_UPDATE, fdb);
	}
}

void fdb_purge_iface(uint16_t iface_id) {
	struct gr_fdb_entry *fdb;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		fdb = data;
		if (fdb->iface_id == iface_id) {
			rte_hash_del_key(fdb_hash, key);
		}
	}
}

void fdb_purge_bridge(uint16_t bridge_id) {
	struct gr_fdb_entry *fdb;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		fdb = data;
		if (fdb->bridge_id == bridge_id) {
			rte_hash_del_key(fdb_hash, key);
		}
	}
}

static struct api_out fdb_add(const void *request, struct api_ctx *) {
	const struct gr_fdb_add_req *req = request;
	const struct iface *iface;
	struct gr_fdb_entry *e;
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
		*e = req->fdb;
		e->bridge_id = iface->id;
		e->last_seen = gr_clock_us();

		if ((ret = rte_hash_add_key_data(fdb_hash, &key, data)) < 0) {
			rte_mempool_put(fdb_pool, e);
			return api_out(-ret, 0, NULL);
		}

		gr_event_push(GR_EVENT_FDB_ADD, e);
	} else if (req->exist_ok) {
		e = data;
		*e = req->fdb;
		e->bridge_id = iface->id;
		e->last_seen = gr_clock_us();

		gr_event_push(GR_EVENT_FDB_UPDATE, e);
	} else {
		return api_out(EEXIST, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct gr_api_handler add_handler = {
	.name = "fdb add",
	.request_type = GR_FDB_ADD,
	.callback = fdb_add,
};

static struct api_out fdb_del(const void *request, struct api_ctx *) {
	const struct gr_fdb_del_req *req = request;
	const struct fdb_key key = {req->bridge_id, req->vlan_id, req->mac};
	int ret;

	ret = rte_hash_del_key(fdb_hash, &key);
	if (ret == -ENOENT && req->missing_ok)
		ret = 0;
	else if (ret > 0)
		ret = 0;

	return api_out(-ret, 0, NULL);
}

static struct gr_api_handler del_handler = {
	.name = "fdb del",
	.request_type = GR_FDB_DEL,
	.callback = fdb_del,
};

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

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		if (!fdb_match(data, req->flags, req->bridge_id, req->iface_id, &req->mac))
			continue;

		ret = rte_hash_del_key(fdb_hash, key);
		if (ret < 0)
			return api_out(-ret, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct gr_api_handler flush_handler = {
	.name = "fdb flush",
	.request_type = GR_FDB_FLUSH,
	.callback = fdb_flush,
};

static struct api_out fdb_list(const void *request, struct api_ctx *ctx) {
	const struct gr_fdb_list_req *req = request;
	struct gr_fdb_entry *fdb;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		if (!fdb_match(data, req->flags, req->bridge_id, req->iface_id, NULL))
			continue;

		fdb = data;
		api_send(ctx, sizeof(*fdb), fdb);
	}

	return api_out(0, 0, NULL);
}

static struct gr_api_handler list_handler = {
	.name = "fdb list",
	.request_type = GR_FDB_LIST,
	.callback = fdb_list,
};

static struct api_out fdb_config_get(const void * /*request*/, struct api_ctx *) {
	struct gr_fdb_config_get_resp *resp = malloc(sizeof(*resp));

	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->max_entries = fdb_max_entries;
	resp->used_entries = rte_hash_count(fdb_hash);

	return api_out(0, sizeof(*resp), resp);
}

static struct gr_api_handler config_get_handler = {
	.name = "fdb config get",
	.request_type = GR_FDB_CONFIG_GET,
	.callback = fdb_config_get,
};

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

static struct gr_api_handler config_set_handler = {
	.name = "fdb config set",
	.request_type = GR_FDB_CONFIG_SET,
	.callback = fdb_config_set,
};

static struct gr_event_serializer serializer = {
	.size = sizeof(struct gr_fdb_entry),
	.ev_count = 3,
	.ev_types = {
		GR_EVENT_FDB_ADD,
		GR_EVENT_FDB_DEL,
		GR_EVENT_FDB_UPDATE,
	},
};

static void fdb_ageing_cb(evutil_socket_t, short /*what*/, void * /*priv*/) {
	const struct iface *bridge;
	struct gr_fdb_entry *fdb;
	uint32_t next = 0;
	uint16_t max_age;
	const void *key;
	clock_t now;
	void *data;
	time_t age;

	now = gr_clock_us();

	while (rte_hash_iterate(fdb_hash, &key, &data, &next) >= 0) {
		fdb = data;

		if ((fdb->flags & GR_FDB_F_STATIC) || !(fdb->flags & GR_FDB_F_LEARN))
			continue;

		age = (now - fdb->last_seen) / CLOCKS_PER_SEC;

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

#define FDB_DEFAULT_MAX_ENTRIES 4096

static void fdb_init(struct event_base *base) {
	if (fdb_reconfig(FDB_DEFAULT_MAX_ENTRIES) < 0)
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

static struct gr_module module = {
	.name = "fdb",
	.depends_on = "rcu",
	.init = fdb_init,
	.fini = fdb_fini,
};

RTE_INIT(init) {
	gr_register_api_handler(&add_handler);
	gr_register_api_handler(&del_handler);
	gr_register_api_handler(&flush_handler);
	gr_register_api_handler(&list_handler);
	gr_register_api_handler(&config_get_handler);
	gr_register_api_handler(&config_set_handler);
	gr_event_register_serializer(&serializer);
	gr_register_module(&module);
}
