// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_clock.h>
#include <gr_event.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_rcu.h>

#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_spinlock.h>

static struct rte_hash *l2_hash;

static int l2_reconfig(const struct gr_nexthop_config *c) {
	char name[64];
	snprintf(name, sizeof(name), "l2-nexthops-%u", c->max_count);

	struct rte_hash_parameters params = {
		.name = name,
		.socket_id = SOCKET_ID_ANY,
		.key_len = sizeof(struct gr_nexthop_info_l2),
		.entries = c->max_count,
	};

	struct rte_hash *h = rte_hash_create(&params);
	if (h == NULL)
		return errno_log(rte_errno, "rte_hash_create");

	struct rte_hash_rcu_config conf = {
		.v = gr_datapath_rcu(),
		.mode = RTE_HASH_QSBR_MODE_SYNC,
	};
	if (rte_hash_rcu_qsbr_add(h, &conf) < 0) {
		rte_hash_free(h);
		return errno_log(rte_errno, "rte_hash_rcu_qsbr_add");
	}

	struct rte_hash *tmp = l2_hash;
	l2_hash = h;
	rte_hash_free(tmp);

	return 0;
}

static struct nexthop *l2_lookup(const struct gr_nexthop_base *, const void *info) {
	const struct gr_nexthop_info_l2 *pub = info;
	return nexthop_lookup_l2(pub->bridge_id, pub->vlan_id, &pub->mac);
}

static bool l2_equal(const struct nexthop *a, const struct nexthop *b) {
	const struct nexthop_info_l2 *l2a = nexthop_info_l2(a);
	const struct nexthop_info_l2 *l2b = nexthop_info_l2(b);

	if (l2a->bridge_id != l2b->bridge_id || l2a->vlan_id != l2b->vlan_id)
		return false;

	return rte_is_same_ether_addr(&l2a->mac, &l2b->mac);
}

static void l2_remove_references(struct nexthop *nh) {
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(l2_hash, &key, &data, &next) >= 0) {
		if (data == nh) {
			rte_hash_del_key(l2_hash, key);
		}
	}
}

static rte_spinlock_t l2_lock;

static int l2_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_l2 *l2 = nexthop_info_l2(nh);
	const struct gr_nexthop_info_l2 *pub = info;
	const struct iface *bridge;
	void *existing = NULL;
	int ret;

	if (pub->vlan_id > RTE_ETHER_MAX_VLAN_ID)
		return errno_set(ERANGE);

	if (rte_is_zero_ether_addr(&pub->mac))
		return errno_set(EINVAL);

	bridge = iface_from_id(pub->bridge_id);
	if (bridge == NULL)
		return -errno;

	if (bridge->type != GR_IFACE_TYPE_BRIDGE)
		return errno_set(EOPNOTSUPP);

	rte_spinlock_lock(&l2_lock);
	if (rte_hash_lookup_data(l2_hash, pub, &existing) >= 0) {
		if (existing != nh) {
			// new key is already in use by another nexthop
			ret = -EADDRINUSE;
		} else {
			// key hasn't changed
			ret = 0;
		}
	} else {
		ret = rte_hash_add_key_data(l2_hash, pub, nh);
		if (ret == 0 && l2->bridge_id != 0) {
			// remove old key from hash table
			rte_hash_del_key(l2_hash, &l2->base);
		}
	}
	rte_spinlock_unlock(&l2_lock);

	if (ret < 0)
		return errno_set(-ret);

	l2->base = *pub;

	return 0;
}

static struct gr_nexthop *l2_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_l2 *l2_priv = nexthop_info_l2(nh);
	struct gr_nexthop_info_l2 *l2_pub;
	struct gr_nexthop *pub;

	pub = malloc(sizeof(*pub) + sizeof(*l2_pub));
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	l2_pub = PAYLOAD(pub);
	*l2_pub = l2_priv->base;

	*len = sizeof(*pub) + sizeof(*l2_pub);

	return pub;
}

struct nexthop *
nexthop_lookup_l2(uint16_t bridge_id, uint16_t vlan_id, const struct rte_ether_addr *mac) {
	const struct gr_nexthop_info_l2 key = {
		.bridge_id = bridge_id,
		.vlan_id = vlan_id,
		.mac = *mac,
	};
	void *data;

	if (rte_hash_lookup_data(l2_hash, &key, &data) < 0)
		return errno_set_null(ENOENT);

	return data;
}

void nexthop_learn_l2(
	uint16_t iface_id,
	uint16_t bridge_id,
	uint16_t vlan_id,
	const struct rte_ether_addr *mac
) {
	const struct gr_nexthop_info_l2 key = {
		.bridge_id = bridge_id,
		.vlan_id = vlan_id,
		.mac = *mac,
	};
	struct nexthop_info_l2 *l2;
	struct nexthop *nh;
	void *data;

	if (rte_hash_lookup_data(l2_hash, &key, &data) < 0) {
		nh = nexthop_new(
			&(struct gr_nexthop_base) {
				.iface_id = iface_id,
				.origin = GR_NH_ORIGIN_BRIDGE,
				.type = GR_NH_T_L2,
			},
			&key
		);
	} else {
		nh = data;
	}

	if (nh != NULL && nh->type == GR_NH_T_L2 && nh->origin == GR_NH_ORIGIN_BRIDGE) {
		// refresh aging timer
		l2 = nexthop_info_l2(nh);
		l2->last_seen = gr_clock_us();
		if (nh->iface_id != iface_id) {
			// update in case the mac address has moved
			nh->iface_id = iface_id;
			gr_event_push(GR_EVENT_NEXTHOP_UPDATE, nh);
		}
	}
}

void nexthop_l2_purge_iface(uint16_t iface_id) {
	struct nexthop *nh;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(l2_hash, &key, &data, &next) >= 0) {
		nh = data;
		if (nh->iface_id == iface_id) {
			rte_hash_del_key(l2_hash, key);
			nexthop_decref(nh);
		}
	}
}

void nexthop_l2_purge_bridge(uint16_t bridge_id) {
	const struct gr_nexthop_info_l2 *l2;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(l2_hash, &key, &data, &next) >= 0) {
		l2 = key;
		if (l2->bridge_id == bridge_id) {
			rte_hash_del_key(l2_hash, key);
			nexthop_decref(data);
		}
	}
}

static void l2_ageing_cb(evutil_socket_t, short /*what*/, void * /*priv*/) {
	clock_t now = gr_clock_us();
	const struct iface *bridge;
	struct nexthop_info_l2 *l2;
	struct nexthop *nh;
	uint32_t next = 0;
	const void *key;
	uint16_t max_age;
	void *data;
	time_t age;

	while (rte_hash_iterate(l2_hash, &key, &data, &next) >= 0) {
		nh = data;

		if (nh->type != GR_NH_T_L2 || nh->origin != GR_NH_ORIGIN_BRIDGE)
			continue;

		l2 = nexthop_info_l2(nh);
		age = (now - l2->last_seen) / CLOCKS_PER_SEC;

		bridge = iface_from_id(l2->bridge_id);
		if (bridge != NULL)
			max_age = iface_info_bridge(bridge)->ageing_time;
		else
			max_age = GR_BRIDGE_DEFAULT_AGEING;

		if (age > max_age) {
			LOG(DEBUG,
			    ETH_F " vlan=%u bridge=%u iface=%u: aged out (%ld sec)",
			    &l2->mac,
			    l2->vlan_id,
			    l2->bridge_id,
			    nh->iface_id,
			    age);
			rte_hash_del_key(l2_hash, key);
			nexthop_decref(nh);
		}
	}
}

static struct nexthop_type_ops l2_ops = {
	.reconfig = l2_reconfig,
	.lookup = l2_lookup,
	.remove_references = l2_remove_references,
	.import_info = l2_import_info,
	.to_api = l2_to_api,
	.equal = l2_equal,
};

static struct event *ageing_timer;

static void l2_init(struct event_base *ev_base) {
	ageing_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, l2_ageing_cb, NULL);
	if (ageing_timer == NULL)
		ABORT("event_new() failed");

	if (event_add(ageing_timer, &(struct timeval) {.tv_sec = 1}) < 0)
		ABORT("event_add() failed");
}

static void l2_fini(struct event_base *) {
	if (ageing_timer)
		event_free(ageing_timer);
	rte_hash_free(l2_hash);
	l2_hash = NULL;
}

static struct gr_module l2_module = {
	.name = "l2",
	.depends_on = "nexthop",
	.init = l2_init,
	.fini = l2_fini,
};

RTE_INIT(l2_nexthop_init) {
	gr_register_module(&l2_module);
	nexthop_type_ops_register(GR_NH_T_L2, &l2_ops);
}
