// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_module.h>
#include <gr_nexthop.h>
#include <gr_nh_control.h>
#include <gr_vec.h>

static struct api_out nh_config_get(const void * /*request*/, void **response) {
	struct gr_infra_nh_config_get_resp *resp = malloc(sizeof(*resp));

	if (resp == NULL)
		return api_out(ENOMEM, 0);

	resp->base = nh_conf;
	resp->used_count = nexthop_used_count();
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct gr_api_handler config_get_handler = {
	.name = "nh config get",
	.request_type = GR_INFRA_NH_CONFIG_GET,
	.callback = nh_config_get,
};

static struct api_out nh_config_set(const void *request, void ** /*response*/) {
	const struct gr_infra_nh_config_set_req *req = request;
	return api_out(-nexthop_config_set(&req->base), 0);
}

static struct gr_api_handler config_set_handler = {
	.name = "nh config set",
	.request_type = GR_INFRA_NH_CONFIG_SET,
	.callback = nh_config_set,
};

static struct api_out nh_add(const void *request, void ** /*response*/) {
	const struct gr_nh_add_req *req = request;
	const struct nexthop_af_ops *ops;
	struct gr_nexthop base = req->nh;
	struct nexthop *nh = NULL;
	struct iface *iface;
	int ret;

	base.flags = 0;
	switch (base.af) {
	case GR_AF_IP4:
		if (base.ipv4 == 0)
			return api_out(EDESTADDRREQ, 0);

		base.flags |= GR_NH_F_GATEWAY;
		break;
	case GR_AF_IP6:
		if (rte_ipv6_addr_is_unspec(&base.ipv6))
			return api_out(EDESTADDRREQ, 0);

		base.flags |= GR_NH_F_GATEWAY;
		break;
	case GR_AF_UNSPEC:
		if (base.ipv4 || !rte_ipv6_addr_is_unspec(&base.ipv6))
			return api_out(EINVAL, 0);

		base.flags |= GR_NH_F_LINK | GR_NH_F_STATIC;
		break;
	default:
		return api_out(ENOPROTOOPT, 0);
	}

	iface = iface_from_id(base.iface_id);
	if (iface == NULL)
		return api_out(errno, 0);

	base.vrf_id = iface->vrf_id;
	base.type = GR_NH_T_L3;
	base.state = GR_NH_S_NEW;
	if (!rte_is_zero_ether_addr(&base.mac)) {
		if (base.af == GR_AF_UNSPEC)
			return api_out(EINVAL, 0);

		base.state = GR_NH_S_REACHABLE;
		base.flags |= GR_NH_F_STATIC;
	}

	if (base.nh_id != GR_NH_ID_UNSET)
		nh = nexthop_lookup_by_id(base.nh_id);

	if (nh == NULL)
		nh = nexthop_lookup(base.af, base.vrf_id, base.iface_id, &base.addr);

	if (nh == NULL) {
		nh = nexthop_new(&base);
		if (nh == NULL)
			return api_out(errno, 0);
		ops = nexthop_af_ops_get(nh->af);
		assert(ops != NULL);
		ret = ops->add(nh);
	} else if (!req->exist_ok) {
		ret = -EEXIST;
	} else {
		// Test the equality on the ipv6 address which encompasses both address families.
		bool need_update = nh->af != base.af || !rte_ipv6_addr_eq(&nh->ipv6, &base.ipv6);
		if (need_update) {
			// Address family or address has changed.
			// Delete the old /32 or /128 route.
			ops = nexthop_af_ops_get(nh->af);
			assert(ops != NULL);
			nexthop_incref(nh); // Prevent ops->del from freeing the nexthop.
			ops->del(nh);
		}
		// Update fields after deleting the route.
		if ((ret = nexthop_update(nh, &base)) < 0) {
			if (need_update)
				nexthop_decref(nh);
			goto end;
		}
		if (need_update) {
			// Re-add the new /32 or /128 route.
			ops = nexthop_af_ops_get(nh->af);
			assert(ops != NULL);
			ret = ops->add(nh);
			nexthop_decref(nh); // ops->add called nexthop_incref if successful.
		} else {
			ret = 0;
		}
		if (ret == 0)
			gr_event_push(GR_EVENT_NEXTHOP_UPDATE, nh);
	}
end:
	return api_out(-ret, 0);
}

static struct gr_api_handler nh_add_handler = {
	.name = "nexthop add",
	.request_type = GR_NH_ADD,
	.callback = nh_add,
};

static struct api_out nh_del(const void *request, void ** /*response*/) {
	const struct gr_nh_del_req *req = request;
	const struct nexthop_af_ops *ops;
	struct nexthop *nh;

	nh = nexthop_lookup_by_id(req->nh.nh_id);
	if (nh == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}

	if ((nh->flags & (GR_NH_F_LOCAL | GR_NH_F_GATEWAY)) || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	ops = nexthop_af_ops_get(nh->af);
	assert(ops != NULL);
	ops->del(nh);

	return api_out(0, 0);
}

static struct gr_api_handler nh_del_handler = {
	.name = "nexthop del",
	.request_type = GR_NH_DEL,
	.callback = nh_del,
};

struct list_context {
	uint16_t vrf_id;
	bool all;
	struct gr_nexthop *nh;
};

static void nh_list_cb(struct nexthop *nh, void *priv) {
	struct list_context *ctx = priv;

	if (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX)
		return;
	if (!ctx->all && nh->origin == GR_NH_ORIGIN_INTERNAL)
		return;

	gr_vec_add(ctx->nh, nh->base);
}

static struct api_out nh_list(const void *request, void **response) {
	const struct gr_nh_list_req *req = request;
	struct list_context ctx = {.vrf_id = req->vrf_id, .all = req->all, .nh = NULL};
	struct gr_nh_list_resp *resp = NULL;
	size_t len;

	nexthop_iter(nh_list_cb, &ctx);

	len = sizeof(*resp) + gr_vec_len(ctx.nh) * sizeof(*ctx.nh);
	if ((resp = calloc(1, len)) == NULL) {
		gr_vec_free(ctx.nh);
		return api_out(ENOMEM, 0);
	}

	resp->n_nhs = gr_vec_len(ctx.nh);
	if (ctx.nh != NULL)
		memcpy(resp->nhs, ctx.nh, resp->n_nhs * sizeof(resp->nhs[0]));
	gr_vec_free(ctx.nh);
	*response = resp;

	return api_out(0, len);
}

static struct gr_api_handler nh_list_handler = {
	.name = "nexthop list",
	.request_type = GR_NH_LIST,
	.callback = nh_list,
};

RTE_INIT(_init) {
	gr_register_api_handler(&config_get_handler);
	gr_register_api_handler(&config_set_handler);
	gr_register_api_handler(&nh_add_handler);
	gr_register_api_handler(&nh_del_handler);
	gr_register_api_handler(&nh_list_handler);
}
