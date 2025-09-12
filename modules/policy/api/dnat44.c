// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_ip4_control.h>
#include <gr_module.h>
#include <gr_nat.h>
#include <gr_nat_control.h>
#include <gr_nat_datapath.h>
#include <gr_vec.h>

static bool dnat44_data_priv_equal(const struct nexthop *a, const struct nexthop *b) {
	struct dnat44_nh_data *ad, *bd;

	assert(a->type == GR_NH_T_DNAT);
	assert(b->type == GR_NH_T_DNAT);

	ad = dnat44_nh_data(a);
	bd = dnat44_nh_data(b);

	return ad->replace == bd->replace;
}

static int dnat44_data_priv_add(
	struct nexthop *nh,
	struct iface *iface,
	ip4_addr_t match,
	ip4_addr_t replace
) {
	struct dnat44_nh_data *data;

	data = dnat44_nh_data(nh);
	data->replace = replace;

	return snat44_static_policy_add(iface, replace, match);
}

static void dnat44_data_priv_del(struct nexthop *nh) {
	struct iface *iface;

	nh->type = GR_NH_T_L3;

	iface = iface_from_id(nh->iface_id);
	if (iface == NULL)
		return;

	snat44_static_policy_del(iface, nh->ipv4);
}

static struct api_out dnat44_add(const void *request, void ** /*response*/) {
	const struct gr_dnat44_add_req *req = request;
	struct iface *iface;
	struct nexthop *nh;
	int ret;

	iface = iface_from_id(req->policy.iface_id);
	if (iface == NULL)
		return api_out(ENODEV, 0);

	nh = nexthop_lookup(GR_AF_IP4, iface->vrf_id, iface->id, &req->policy.match);
	if (nh != NULL) {
		if (nh->type == GR_NH_T_DNAT && req->exist_ok)
			return api_out(0, 0);
		return api_out(EADDRINUSE, 0);
	}

	nh = nexthop_new(&(struct gr_nexthop) {
		.type = GR_NH_T_DNAT,
		.af = GR_AF_IP4,
		.flags = GR_NH_F_LOCAL | GR_NH_F_STATIC,
		.state = GR_NH_S_REACHABLE,
		.vrf_id = iface->vrf_id,
		.iface_id = iface->id,
		.ipv4 = req->policy.match,
		.origin = GR_NH_ORIGIN_INTERNAL,
	});
	if (nh == NULL)
		return api_out(ENOMEM, 0);

	ret = dnat44_data_priv_add(nh, iface, req->policy.match, req->policy.replace);
	if (ret < 0) {
		if (ret == -EEXIST && req->exist_ok)
			ret = 0;

		nexthop_decref(nh);
		return api_out(-ret, 0);
	}

	ret = rib4_insert(iface->vrf_id, req->policy.match, 32, GR_NH_ORIGIN_INTERNAL, nh);
	if (ret == -EEXIST && req->exist_ok)
		ret = 0;

	return api_out(-ret, 0);
}

static struct api_out dnat44_del(const void *request, void ** /*response*/) {
	const struct gr_dnat44_del_req *req = request;
	struct iface *iface;
	int ret;

	iface = iface_from_id(req->iface_id);
	if (iface == NULL)
		return api_out(ENODEV, 0);

	ret = rib4_delete(iface->vrf_id, req->match, 32, GR_NH_T_DNAT);
	if (ret == -ENOENT && req->missing_ok)
		ret = 0;

	return api_out(-ret, 0);
}

struct dnat44_list_iterator {
	uint16_t vrf_id;
	gr_vec struct gr_dnat44_policy *policies;
};

static void dnat44_list_iter(struct nexthop *nh, void *priv) {
	struct dnat44_list_iterator *iter = priv;
	struct dnat44_nh_data *data;

	if (iter->vrf_id != GR_VRF_ID_ALL && nh->vrf_id != iter->vrf_id)
		return;

	if (nh->type != GR_NH_T_DNAT)
		return;

	data = dnat44_nh_data(nh);

	struct gr_dnat44_policy policy = {
		.iface_id = nh->iface_id,
		.match = nh->ipv4,
		.replace = data->replace,
	};
	gr_vec_add(iter->policies, policy);
}

static struct api_out dnat44_list(const void *request, void **response) {
	const struct gr_dnat44_list_req *req = request;
	struct gr_dnat44_list_resp *resp;
	struct dnat44_list_iterator iter = {
		.vrf_id = req->vrf_id,
		.policies = NULL,
	};
	size_t len;

	nexthop_iter(dnat44_list_iter, &iter);

	len = sizeof(*resp) + gr_vec_len(iter.policies) * sizeof(struct gr_dnat44_policy);
	resp = malloc(len);
	if (resp == NULL) {
		gr_vec_free(iter.policies);
		return api_out(ENOMEM, 0);
	}

	resp->n_policies = gr_vec_len(iter.policies);
	memcpy(resp->policies,
	       iter.policies,
	       gr_vec_len(iter.policies) * sizeof(struct gr_dnat44_policy));
	gr_vec_free(iter.policies);

	*response = resp;

	return api_out(0, len);
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
	.equal = dnat44_data_priv_equal,
	.free = dnat44_data_priv_del,
};

RTE_INIT(_init) {
	gr_register_api_handler(&add_handler);
	gr_register_api_handler(&del_handler);
	gr_register_api_handler(&list_handler);
	nexthop_type_ops_register(GR_NH_T_DNAT, &nh_ops);
}
