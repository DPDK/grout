// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_ip4_control.h>
#include <gr_module.h>
#include <gr_nat.h>
#include <gr_nat_control.h>
#include <gr_nat_datapath.h>
#include <gr_vec.h>

static struct nexthop *dnat44_nh_lookup(const struct gr_nexthop_base *base, const void *info) {
	const struct iface *iface = iface_from_id(base->iface_id);
	const struct gr_nexthop_info_dnat *dnat = info;
	struct nexthop *nh;

	if (iface == NULL)
		return NULL;

	nh = rib4_lookup_exact(iface->vrf_id, dnat->match, 32);
	if (nh == NULL || nh->type != GR_NH_T_DNAT)
		return NULL;

	return nh;
}

static bool dnat44_nh_equal(const struct nexthop *a, const struct nexthop *b) {
	struct nexthop_info_dnat *ad = nexthop_info_dnat(a);
	struct nexthop_info_dnat *bd = nexthop_info_dnat(b);

	return ad->match == bd->match && ad->replace == bd->replace;
}

static void dnat44_nh_remove_references(struct nexthop *nh) {
	if (nh->type == GR_NH_T_DNAT) {
		struct nexthop_info_dnat *dnat = nexthop_info_dnat(nh);
		struct iface *iface = iface_from_id(nh->iface_id);
		if (iface == NULL)
			return;
		snat44_static_policy_del(iface, dnat->replace);
	}
}

static void dnat44_nh_free(struct nexthop *nh) {
	struct nexthop_info_dnat *dnat = nexthop_info_dnat(nh);
	if (dnat->arp)
		nexthop_decref(dnat->arp);
	dnat->arp = NULL;
}

static int dnat44_nh_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_dnat *priv = nexthop_info_dnat(nh);
	const struct gr_nexthop_info_dnat *pub = info;
	ip4_addr_t old_replace = priv->replace;
	ip4_addr_t old_match = priv->match;
	struct nexthop *arp = NULL;
	struct iface *iface;

	iface = iface_from_id(nh->iface_id);
	if (iface == NULL)
		return -errno;

	if (priv->arp == NULL || pub->match != old_match) {
		// Add an internal L3 nexthop to respond to ARP requests.
		arp = nexthop_new(
			&(struct gr_nexthop_base) {
				.type = GR_NH_T_L3,
				.iface_id = iface->id,
				.vrf_id = iface->vrf_id,
				.origin = GR_NH_ORIGIN_INTERNAL,
			},
			&(struct gr_nexthop_info_l3) {
				.af = GR_AF_IP4,
				.flags = GR_NH_F_STATIC | GR_NH_F_LOCAL,
				.ipv4 = pub->match,
			}
		);
		if (arp == NULL)
			return -errno;
	}

	// Add new SNAT policy if addresses have changed.
	if (pub->replace != old_replace || pub->match != old_match) {
		int ret = snat44_static_policy_add(iface, pub->replace, pub->match);
		if (ret < 0) {
			if (arp != NULL)
				nexthop_decref(arp);
			return errno_set(-ret);
		}
	}

	// Update all fields.
	priv->base = *pub;
	if (arp != NULL) {
		struct nexthop *old_arp = priv->arp;
		priv->arp = arp;
		if (old_arp != NULL)
			nexthop_decref(old_arp);
	}

	// Delete old policy if any.
	if (pub->replace != old_replace && old_replace != 0)
		snat44_static_policy_del(iface, old_replace);

	return 0;
}

static struct gr_nexthop *dnat44_nh_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_dnat *dnat_priv = nexthop_info_dnat(nh);
	struct gr_nexthop_info_dnat *dnat_pub;
	struct gr_nexthop *pub;

	pub = malloc(sizeof(*pub) + sizeof(*dnat_pub));
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	dnat_pub = (struct gr_nexthop_info_dnat *)pub->info;
	*dnat_pub = dnat_priv->base;

	*len = sizeof(*pub) + sizeof(*dnat_pub);

	return pub;
}

static struct api_out dnat44_add(const void *request, struct api_ctx *) {
	const struct gr_dnat44_add_req *req = request;
	struct iface *iface;
	struct nexthop *nh;
	ip4_addr_t replace;

	if (snat44_static_lookup_translation(req->policy.iface_id, req->policy.match, &replace)) {
		if (req->exist_ok && replace == req->policy.replace)
			return api_out(0, 0, NULL);
		return api_out(EEXIST, 0, NULL);
	}

	iface = iface_from_id(req->policy.iface_id);
	if (iface == NULL)
		return api_out(ENODEV, 0, NULL);

	nh = nexthop_lookup_l3(GR_AF_IP4, iface->vrf_id, iface->id, &req->policy.match);
	if (nh != NULL) {
		if (nh->type == GR_NH_T_DNAT && req->exist_ok)
			return api_out(0, 0, NULL);
		return api_out(EADDRINUSE, 0, NULL);
	}

	nh = nexthop_new(
		&(struct gr_nexthop_base) {
			.type = GR_NH_T_DNAT,
			.iface_id = iface->id,
			.origin = GR_NH_ORIGIN_INTERNAL,
		},
		&(struct gr_nexthop_info_dnat) {
			.match = req->policy.match,
			.replace = req->policy.replace,
		}
	);
	if (nh == NULL)
		return api_out(errno, 0, NULL);

	if (rib4_insert(iface->vrf_id, req->policy.match, 32, GR_NH_ORIGIN_INTERNAL, nh) < 0) {
		nexthop_decref(nh);
		return api_out(errno, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct api_out dnat44_del(const void *request, struct api_ctx *) {
	const struct gr_dnat44_del_req *req = request;
	struct iface *iface;
	int ret;

	iface = iface_from_id(req->iface_id);
	if (iface == NULL)
		return api_out(ENODEV, 0, NULL);

	ret = rib4_delete(iface->vrf_id, req->match, 32, GR_NH_T_DNAT);
	if (ret == -ENOENT && req->missing_ok)
		ret = 0;

	return api_out(-ret, 0, NULL);
}

struct dnat44_list_iterator {
	uint16_t vrf_id;
	struct api_ctx *ctx;
};

static void dnat44_list_iter(struct nexthop *nh, void *priv) {
	struct dnat44_list_iterator *iter = priv;
	const struct nexthop_info_dnat *dnat;
	const struct iface *iface;

	if (nh->type != GR_NH_T_DNAT)
		return;

	dnat = nexthop_info_dnat(nh);
	iface = iface_from_id(nh->iface_id);
	if (iface == NULL)
		return;

	if (iter->vrf_id != GR_VRF_ID_ALL && iface->vrf_id != iter->vrf_id)
		return;

	struct gr_dnat44_policy policy = {
		.iface_id = nh->iface_id,
		.match = dnat->match,
		.replace = dnat->replace,
	};
	api_send(iter->ctx, sizeof(policy), &policy);
}

static struct api_out dnat44_list(const void *request, struct api_ctx *ctx) {
	const struct gr_dnat44_list_req *req = request;
	struct dnat44_list_iterator iter = {
		.vrf_id = req->vrf_id,
		.ctx = ctx,
	};

	nexthop_iter(dnat44_list_iter, &iter);

	return api_out(0, 0, NULL);
}

static struct gr_api_handler add_handler = {
	.name = "dnat44 add",
	.request_type = GR_DNAT44_ADD,
	.callback = dnat44_add,
};
static struct gr_api_handler del_handler = {
	.name = "dnat44 del",
	.request_type = GR_DNAT44_DEL,
	.callback = dnat44_del,
};
static struct gr_api_handler list_handler = {
	.name = "dnat44 list",
	.request_type = GR_DNAT44_LIST,
	.callback = dnat44_list,
};

static struct nexthop_type_ops nh_ops = {
	.lookup = dnat44_nh_lookup,
	.equal = dnat44_nh_equal,
	.remove_references = dnat44_nh_remove_references,
	.free = dnat44_nh_free,
	.import_info = dnat44_nh_import_info,
	.to_api = dnat44_nh_to_api,
};

RTE_INIT(_init) {
	gr_register_api_handler(&add_handler);
	gr_register_api_handler(&del_handler);
	gr_register_api_handler(&list_handler);
	nexthop_type_ops_register(GR_NH_T_DNAT, &nh_ops);
}
