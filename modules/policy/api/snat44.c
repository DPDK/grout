// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "ip4.h"
#include "module.h"
#include "nat.h"
#include "vec.h"

#include <gr_nat.h>

static struct api_out snat44_add(const void *request, struct api_ctx *) {
	const struct gr_snat44_add_req *req = request;
	struct iface *iface;
	int ret;

	iface = iface_from_id(req->policy.iface_id);
	if (iface == NULL)
		return api_out(ENODEV, 0, NULL);

	if (nh4_lookup(iface->vrf_id, req->policy.replace) == NULL)
		return api_out(EADDRNOTAVAIL, 0, NULL);

	ret = snat44_dynamic_policy_add(&req->policy);
	if (ret == -EEXIST && req->exist_ok)
		ret = 0;

	return api_out(-ret, 0, NULL);
}

static struct api_out snat44_del(const void *request, struct api_ctx *) {
	const struct gr_snat44_del_req *req = request;
	int ret;

	ret = snat44_dynamic_policy_del(&req->policy);
	if (ret == -ENOENT && req->missing_ok)
		ret = 0;

	return api_out(-ret, 0, NULL);
}

static struct api_out snat44_list(const void * /*request*/, struct api_ctx *ctx) {
	gr_vec struct gr_snat44_policy *policies;
	struct gr_snat44_policy *policy;

	policies = snat44_dynamic_policy_export();
	gr_vec_foreach_ref (policy, policies) {
		api_send(ctx, sizeof(*policy), policy);
	}
	gr_vec_free(policies);

	return api_out(0, 0, NULL);
}

RTE_INIT(_init) {
	gr_api_handler(GR_SNAT44_ADD, snat44_add);
	gr_api_handler(GR_SNAT44_DEL, snat44_del);
	gr_api_handler(GR_SNAT44_LIST, snat44_list);
}
