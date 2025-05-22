// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_ip4.h>
#include <gr_ip4_datapath.h>
#include <gr_module.h>
#include <gr_vec.h>

static struct api_out dnat44_add(const void *request, void ** /*response*/) {
	const struct gr_dnat44_add_req *req = request;
	bool allocated_repl = false;
	struct iface *iface;
	struct nexthop *nh;
	int ret;

	iface = iface_from_id(req->rule.iface_id);
	if (iface == NULL)
		return api_out(ENODEV, 0);

	nh = nh4_lookup(iface->vrf_id, req->rule.match);
	if (nh != NULL) {
		if (!(nh->flags & GR_NH_F_DNAT) || nh->priv.ipv4 != req->rule.replace)
			return api_out(EADDRINUSE, 0);
		if (req->exist_ok)
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	nh = nh4_new(iface->vrf_id, iface->id, req->rule.match);
	if (nh == NULL)
		return api_out(ENOMEM, 0);

	nh->flags = GR_NH_F_LOCAL | GR_NH_F_STATIC | GR_NH_F_REACHABLE | GR_NH_F_DNAT;
	nh->priv.ipv4 = req->rule.replace;
	ret = rib4_insert(iface->vrf_id, req->rule.match, 32, GR_RT_ORIGIN_INTERNAL, nh);
	if (ret < 0)
		return api_out(-ret, 0);

	nh = rib4_lookup(iface->vrf_id, req->rule.replace);
	if (nh == NULL) {
		ret = -ENETUNREACH;
		goto fail;
	}

	if (nh->ipv4 != req->rule.replace) {
		nh = nh4_new(iface->vrf_id, nh->iface_id, req->rule.replace);
		if (nh == NULL) {
			ret = -ENOMEM;
			goto fail;
		}
		ret = rib4_insert(iface->vrf_id, nh->ipv4, 32, GR_RT_ORIGIN_INTERNAL, nh);
		if (ret < 0)
			goto fail;
		allocated_repl = true;
	}

	nh->flags |= GR_NH_F_SNAT;
	nh->priv.ipv4 = req->rule.match;
	iface->flags |= GR_IFACE_F_SNAT;

	return api_out(0, 0);
fail:
	rib4_delete(iface->vrf_id, req->rule.match, 32);
	if (allocated_repl)
		rib4_delete(iface->vrf_id, req->rule.replace, 32);
	return api_out(-ret, 0);
}

struct dnat44_iface_iterator {
	uint16_t iface_id;
	unsigned count;
};

static void dnat44_iface_iter(struct nexthop *nh, void *priv) {
	struct dnat44_iface_iterator *iter = priv;
	if (iter->iface_id == nh->iface_id && (nh->flags & GR_NH_F_DNAT))
		iter->count++;
}

static struct api_out dnat44_del(const void *request, void ** /*response*/) {
	const struct gr_dnat44_del_req *req = request;
	struct iface *iface;
	struct nexthop *nh;

	iface = iface_from_id(req->rule.iface_id);
	if (iface == NULL)
		return api_out(ENODEV, 0);

	nh = nh4_lookup(iface->vrf_id, req->rule.match);
	if (nh == NULL || !(nh->flags & GR_NH_F_DNAT) || nh->priv.ipv4 != req->rule.replace) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}

	rib4_delete(iface->vrf_id, req->rule.match, 32);

	nh = nh4_lookup(iface->vrf_id, req->rule.replace);
	if (nh == NULL || !(nh->flags & GR_NH_F_SNAT) || nh->priv.ipv4 != req->rule.match)
		return api_out(EIDRM, 0);

	rib4_delete(iface->vrf_id, req->rule.replace, 32);

	struct dnat44_iface_iterator iter = {
		.iface_id = iface->id,
		.count = 0,
	};
	nexthop_iter(dnat44_iface_iter, &iter);
	if (iter.count == 0)
		iface->flags &= ~GR_IFACE_F_SNAT;

	return api_out(0, 0);
}

struct dnat44_list_iterator {
	uint16_t vrf_id;
	struct gr_dnat44_rule *rules;
};

static void dnat44_list_iter(struct nexthop *nh, void *priv) {
	struct dnat44_list_iterator *iter = priv;

	if (iter->vrf_id != GR_VRF_ID_ALL && nh->vrf_id != iter->vrf_id)
		return;

	if (!(nh->flags & GR_NH_F_DNAT))
		return;

	struct gr_dnat44_rule rule = {
		.iface_id = nh->iface_id,
		.match = nh->ipv4,
		.replace = nh->priv.ipv4,
	};
	gr_vec_add(iter->rules, rule);
}

static struct api_out dnat44_list(const void *request, void **response) {
	const struct gr_dnat44_list_req *req = request;
	struct gr_dnat44_list_resp *resp;
	struct dnat44_list_iterator iter = {
		.vrf_id = req->vrf_id,
		.rules = NULL,
	};
	size_t len;

	nexthop_iter(dnat44_list_iter, &iter);

	len = sizeof(*resp) + gr_vec_len(iter.rules) * sizeof(struct gr_dnat44_rule);
	resp = malloc(len);
	if (resp == NULL) {
		free(iter.rules);
		return api_out(ENOMEM, 0);
	}

	resp->n_rules = gr_vec_len(iter.rules);
	memcpy(resp->rules, iter.rules, gr_vec_len(iter.rules) * sizeof(struct gr_dnat44_rule));
	gr_vec_free(iter.rules);

	*response = resp;

	return api_out(0, len);
}

static struct gr_api_handler add_handler = {
	.name = "nat44 add",
	.request_type = GR_DNAT44_ADD,
	.callback = dnat44_add,
};
static struct gr_api_handler del_handler = {
	.name = "nat44 del",
	.request_type = GR_DNAT44_DEL,
	.callback = dnat44_del,
};
static struct gr_api_handler list_handler = {
	.name = "nat44 list",
	.request_type = GR_DNAT44_LIST,
	.callback = dnat44_list,
};

RTE_INIT(_init) {
	gr_register_api_handler(&add_handler);
	gr_register_api_handler(&del_handler);
	gr_register_api_handler(&list_handler);
}
