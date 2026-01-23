// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_clock.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_module.h>
#include <gr_nh_control.h>
#include <gr_rcu.h>

#include <rte_hash.h>

#include <stdint.h>

static struct rte_hash *l3_hash;
static struct event *ageing_timer;
static const struct nexthop_af_ops *af_ops[256];

void nexthop_af_ops_register(addr_family_t af, const struct nexthop_af_ops *ops) {
	if (!gr_af_valid(af))
		ABORT("invalid af value %hhu", af);
	if (ops == NULL || ops->cleanup_routes == NULL || ops->solicit == NULL)
		ABORT("invalid af ops");
	if (af_ops[af] != NULL)
		ABORT("duplicate af ops %s", gr_af_name(af));
	af_ops[af] = ops;
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

struct nexthop *
nexthop_lookup_l3(addr_family_t af, uint16_t vrf_id, uint16_t iface_id, const void *addr) {
	struct nexthop_key key;
	void *data;

	if (af == AF_UNSPEC)
		return NULL;

	set_nexthop_key(&key, af, vrf_id, iface_id, addr);

	if (rte_hash_lookup_data(l3_hash, &key, &data) < 0)
		return errno_set_null(ENOENT);

	return data;
}

static struct nexthop *l3_lookup(const struct gr_nexthop_base *base, const void *info) {
	const struct iface *iface = iface_from_id(base->iface_id);
	const struct gr_nexthop_info_l3 *l3 = info;
	uint16_t vrf_id = base->vrf_id;

	if (iface != NULL)
		vrf_id = iface->vrf_id;

	return nexthop_lookup_l3(l3->af, vrf_id, base->iface_id, &l3->addr);
}

static int l3_reconfig(const struct gr_nexthop_config *c) {
	char name[64];
	snprintf(name, sizeof(name), "nexthop-l3-%u", c->max_count);

	struct rte_hash_parameters params = {
		.name = name,
		.socket_id = SOCKET_ID_ANY,
		.key_len = sizeof(struct nexthop_key),
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

	struct rte_hash *tmp = l3_hash;
	l3_hash = h;
	rte_hash_free(tmp);

	return 0;
}

void nexthop_routes_cleanup(struct nexthop *nh) {
	const struct nexthop_af_ops *ops;
	for (unsigned i = 0; i < ARRAY_DIM(af_ops); i++) {
		ops = af_ops[i];
		if (ops != NULL)
			ops->cleanup_routes(nh);
	}
}

static void l3_free(struct nexthop *nh) {
	struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);

	if (l3->ipv4 != 0 || !rte_ipv6_addr_is_unspec(&l3->ipv6)) {
		struct nexthop_key key;
		set_nexthop_key(&key, l3->af, nh->vrf_id, nh->iface_id, &l3->addr);
		rte_hash_del_key(l3_hash, &key);
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
	struct nexthop_key old_key, key;
	bool has_old_addr, has_new_addr;
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

	// Check that the new address isn't already in use by a different nexthop
	has_new_addr = pub->ipv4 != 0 || !rte_ipv6_addr_is_unspec(&pub->ipv6);
	if (has_new_addr) {
		void *existing;
		set_nexthop_key(&key, pub->af, nh->vrf_id, nh->iface_id, &pub->addr);
		if (rte_hash_lookup_data(l3_hash, &key, &existing) >= 0 && existing != nh)
			return errno_set(EADDRINUSE);
	}

	has_old_addr = priv.ipv4 != 0 || !rte_ipv6_addr_is_unspec(&priv.ipv6);
	if (has_old_addr)
		set_nexthop_key(&old_key, priv.af, nh->vrf_id, nh->iface_id, &priv.addr);

	// Copy new fields in the private info section.
	priv.ipv6 = pub->ipv6; // ipv6 encompasses ipv4
	priv.af = pub->af;
	priv.prefixlen = pub->prefixlen;

	if (has_new_addr) {
		// Add new entry in hash table for fast lookup.
		if ((ret = rte_hash_add_key_data(l3_hash, &key, nh)) < 0)
			return errno_set(-ret);
	}

	// Delete old entry only if key has changed.
	if (has_old_addr && (!has_new_addr || memcmp(&old_key, &key, sizeof(old_key)) != 0))
		rte_hash_del_key(l3_hash, &old_key);

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
	.reconfig = l3_reconfig,
	.lookup = l3_lookup,
	.free = l3_free,
	.equal = l3_equal,
	.import_info = l3_import_info,
	.to_api = l3_to_api,
};

static void l3_age(struct nexthop *nh, struct nexthop_info_l3 *l3) {
	const struct nexthop_af_ops *ops;
	clock_t now = gr_clock_us();
	unsigned probes, max_probes;
	time_t reply_age;

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
	struct nexthop_info_l3 *l3;
	uint32_t next = 0;
	const void *key;
	void *data;

	while (rte_hash_iterate(l3_hash, &key, &data, &next) >= 0) {
		l3 = nexthop_info_l3(data);

		if (l3->flags & GR_NH_F_STATIC)
			continue;

		l3_age(data, l3);
	}
}

static void l3_init(struct event_base *ev_base) {
	ageing_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, do_ageing, NULL);
	if (ageing_timer == NULL)
		ABORT("event_new() failed");

	if (event_add(ageing_timer, &(struct timeval) {.tv_sec = 1}) < 0)
		ABORT("event_add() failed");
}

static void l3_fini(struct event_base *) {
	rte_hash_free(l3_hash);
	if (ageing_timer)
		event_free(ageing_timer);
}

static struct gr_module module = {
	.name = "l3_nexthop",
	.depends_on = "nexthop",
	.init = l3_init,
	.fini = l3_fini,
};

RTE_INIT(init) {
	gr_register_module(&module);
	nexthop_type_ops_register(GR_NH_T_L3, &l3_nh_ops);
}
