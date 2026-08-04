// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include "iface.h"
#include "log.h"
#include "module.h"
#include "rcu.h"
#include "srv6.h"

#include <gr_srv6.h>

#include <rte_hash.h>

LOG_TYPE("srv6");

static struct rte_hash *srv6_local_hash;

// Hash key for SRv6 local nexthop lookup (26 bytes).
// Includes all fields checked during lookup.
struct srv6_local_key {
	struct rte_ipv6_addr endx_addr; // 16 bytes (zeros for non-END.X)
	uint16_t vrf_id; //  2 bytes
	uint16_t iface_id; //  2 bytes
	gr_srv6_behavior_t behavior; //  2 bytes
	uint16_t out_vrf_id; //  2 bytes
	gr_srv6_flags_t flags; //  1 byte
	uint8_t _pad; //  1 byte
};

static inline void set_srv6_local_key(
	struct srv6_local_key *key,
	const struct gr_nexthop_base *base,
	const struct gr_nexthop_info_srv6_local *info
) {
	memset(key, 0, sizeof(*key));
	key->vrf_id = base->vrf_id;
	key->iface_id = base->iface_id;
	key->behavior = info->behavior;
	key->out_vrf_id = info->out_vrf_id;
	key->flags = info->flags;

	// Only set endx_addr for END.X behavior
	if (info->behavior == SR_BEHAVIOR_END_X)
		key->endx_addr = info->endx_addr;
}

static int srv6_local_reconfig(const struct gr_nexthop_config *c) {
	char name[64];
	snprintf(name, sizeof(name), "nexthop-srv6-local-%u", c->max_count);

	struct rte_hash_parameters params = {
		.name = name,
		.socket_id = SOCKET_ID_ANY,
		.key_len = sizeof(struct srv6_local_key),
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

	struct rte_hash *tmp = srv6_local_hash;
	srv6_local_hash = h;
	rte_hash_free(tmp);

	return 0;
}

static bool srv6_local_nh_equal(const struct nexthop *a, const struct nexthop *b) {
	struct nexthop_info_srv6_local *ad = nexthop_info_srv6_local(a);
	struct nexthop_info_srv6_local *bd = nexthop_info_srv6_local(b);

	if (ad->behavior != bd->behavior || ad->out_vrf_id != bd->out_vrf_id
	    || ad->flags != bd->flags || ad->block_bits != bd->block_bits
	    || ad->csid_bits != bd->csid_bits)
		return false;

	if (ad->behavior == SR_BEHAVIOR_END_X) {
		if (!rte_ipv6_addr_eq(&ad->endx_addr, &bd->endx_addr))
			return false;
	}

	return true;
}

static struct nexthop *srv6_local_nh_lookup(const struct gr_nexthop_base *base, const void *info) {
	struct srv6_local_key key;
	void *data;

	set_srv6_local_key(&key, base, info);

	if (rte_hash_lookup_data(srv6_local_hash, &key, &data) < 0)
		return errno_set_null(ENOENT);

	return data;
}

static int srv6_local_nh_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_srv6_local *priv = nexthop_info_srv6_local(nh);
	const struct gr_nexthop_info_srv6_local *pub = info;
	struct nexthop *l3_nh = NULL;
	uint8_t block_bits = pub->block_bits;
	uint8_t csid_bits = pub->csid_bits;

	if (pub->flags & GR_SR_FL_FLAVOR_NEXT_CSID) {
		if (block_bits == 0)
			block_bits = 32;
		if (csid_bits == 0)
			csid_bits = 16;
		if (block_bits % CHAR_BIT != 0 || csid_bits % CHAR_BIT != 0)
			return errno_set(EDOM);
		if (block_bits + csid_bits > RTE_IPV6_MAX_DEPTH)
			return errno_set(ERANGE);
	}

	// Update all fields
	priv->base = *pub;
	priv->block_bits = block_bits;
	priv->csid_bits = csid_bits;

	if (pub->behavior == SR_BEHAVIOR_END_X) {
		// Validate END.X requires interface and address
		if (nh->iface_id == 0)
			return errno_set(EINVAL);

		// Get interface to determine correct VRF
		const struct iface *iface = iface_from_id(nh->iface_id);
		if (iface == NULL)
			return errno_set(ENODEV);

		// Resolve L3 nexthop by address and interface
		// Use interface's VRF to match l3_lookup() behavior
		l3_nh = nexthop_lookup_l3(GR_AF_IP6, iface->vrf_id, nh->iface_id, &pub->endx_addr);

		if (l3_nh == NULL) {
			// L3 nexthop doesn't exist - create it for FRR
			struct gr_nexthop_base base = {
				.type = GR_NH_T_L3,
				.origin = GR_NH_ORIGIN_INTERNAL,
				.iface_id = nh->iface_id,
				.vrf_id = iface->vrf_id, // Use interface's VRF
			};
			struct gr_nexthop_info_l3 l3_info = {
				.af = GR_AF_IP6,
				.ipv6 = pub->endx_addr,
			};

			l3_nh = nexthop_new(&base, &l3_info);
			if (l3_nh == NULL)
				return -errno;

			// Validate L3 nexthop
			if (l3_nh->type != GR_NH_T_L3) {
				nexthop_decref(l3_nh);
				return errno_set(EINVAL);
			}

			const struct nexthop_info_l3 *l3 = nexthop_info_l3(l3_nh);
			if (l3->af != GR_AF_IP6) {
				nexthop_decref(l3_nh);
				return errno_set(EINVAL);
			}

			// Store newly created L3 nexthop (already has ref_count=1)
			if (priv->l3_nh)
				nexthop_decref(priv->l3_nh);
			priv->l3_nh = l3_nh;

		} else if (l3_nh != priv->l3_nh) {
			struct nexthop *old_l3_nh = priv->l3_nh;

			// Validate looked-up L3 nexthop before taking reference
			if (l3_nh->type != GR_NH_T_L3)
				return errno_set(EINVAL);

			const struct nexthop_info_l3 *l3 = nexthop_info_l3(l3_nh);
			if (l3->af != GR_AF_IP6)
				return errno_set(EINVAL);

			// Take reference to existing L3 nexthop
			nexthop_incref(l3_nh);
			priv->l3_nh = l3_nh;
			if (old_l3_nh)
				nexthop_decref(old_l3_nh);
		}

	} else {
		priv->l3_nh = NULL;
	}

	// Add to hash table for fast lookup
	struct srv6_local_key key;
	set_srv6_local_key(&key, &nh->base, pub);

	int ret = rte_hash_add_key_data(srv6_local_hash, &key, nh);
	if (ret < 0)
		return errno_set(-ret);

	return 0;
}

static struct gr_nexthop *srv6_local_nh_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_srv6_local *sr6_priv = nexthop_info_srv6_local(nh);
	struct gr_nexthop_info_srv6_local *sr6_pub;
	struct gr_nexthop *pub;

	pub = malloc(sizeof(*pub) + sizeof(*sr6_pub));
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	sr6_pub = (struct gr_nexthop_info_srv6_local *)pub->info;
	*sr6_pub = sr6_priv->base;

	*len = sizeof(*pub) + sizeof(*sr6_pub);

	return pub;
}

static void srv6_local_remove_references(struct nexthop *nh) {
	if (nh->type == GR_NH_T_SR6_LOCAL) {
		struct nexthop_info_srv6_local *priv = nexthop_info_srv6_local(nh);
		struct srv6_local_key key;

		set_srv6_local_key(&key, &nh->base, &priv->base);
		rte_hash_del_key(srv6_local_hash, &key);
	}
}

static void srv6_local_nh_free(struct nexthop *nh) {
	// Free function is called after ref_count has been driven to 0
	// by nexthop cleanup, which force-decrefs all references.
	// At this point, any references we held have already been released.
	// Nothing to do here.
	(void)nh;
}

static struct nexthop_type_ops nh_ops = {
	.reconfig = srv6_local_reconfig,
	.equal = srv6_local_nh_equal,
	.lookup = srv6_local_nh_lookup,
	.import_info = srv6_local_nh_import_info,
	.to_api = srv6_local_nh_to_api,
	.remove_references = srv6_local_remove_references,
	.free = srv6_local_nh_free,
};

static void srv6_local_fini(struct event_base *) {
	rte_hash_free(srv6_local_hash);
}

static struct module module = {
	.name = "srv6_local",
	.depends_on = "nexthop",
	.fini = srv6_local_fini,
};

RTE_INIT(srv6_constructor) {
	module_register(&module);
	nexthop_type_ops_register(GR_NH_T_SR6_LOCAL, &nh_ops);
}
