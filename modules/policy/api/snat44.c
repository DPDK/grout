// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_ip4_control.h>
#include <gr_module.h>
#include <gr_nat.h>
#include <gr_nat_control.h>
#include <gr_vec.h>

static struct api_out snat44_add(const void *request, void ** /*response*/) {
	const struct gr_snat44_add_req *req = request;
	struct iface *iface;
	int ret;

	iface = iface_from_id(req->policy.iface_id);
	if (iface == NULL)
		return api_out(ENODEV, 0);

	if (nh4_lookup(iface->vrf_id, req->policy.replace) == NULL)
		return api_out(EADDRNOTAVAIL, 0);

	ret = snat44_dynamic_policy_add(&req->policy);
	if (ret == -EEXIST && req->exist_ok)
		ret = 0;

	return api_out(-ret, 0);
}

static struct api_out snat44_del(const void *request, void ** /*response*/) {
	const struct gr_snat44_del_req *req = request;
	int ret;

	ret = snat44_dynamic_policy_del(&req->policy);
	if (ret == -ENOENT && req->missing_ok)
		ret = 0;

	return api_out(-ret, 0);
}

static struct api_out snat44_list(const void * /*request*/, void **response) {
	gr_vec struct gr_snat44_policy *policies;
	struct gr_snat44_list_resp *resp;
	size_t len;

	policies = snat44_dynamic_policy_export();
	len = sizeof(*resp) + gr_vec_len(policies) * sizeof(*policies);
	resp = malloc(len);
	if (resp == NULL) {
		gr_vec_free(policies);
		return api_out(ENOMEM, 0);
	}

	resp->n_policies = gr_vec_len(policies);
	memcpy(resp->policies, policies, gr_vec_len(policies) * sizeof(*policies));
	gr_vec_free(policies);

	*response = resp;

	return api_out(0, len);
}

static struct gr_api_handler add_handler = {
	.name = "snat44 add",
	.request_type = GR_SNAT44_ADD,
	.callback = snat44_add,
};
static struct gr_api_handler del_handler = {
	.name = "snat44 del",
	.request_type = GR_SNAT44_DEL,
	.callback = snat44_del,
};
static struct gr_api_handler list_handler = {
	.name = "snat44 list",
	.request_type = GR_SNAT44_LIST,
	.callback = snat44_list,
};

RTE_INIT(_init) {
	gr_register_api_handler(&add_handler);
	gr_register_api_handler(&del_handler);
	gr_register_api_handler(&list_handler);
}
