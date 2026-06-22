// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "event.h"
#include "module.h"
#include "mpls.h"

#include <gr_mpls.h>

static struct api_out label_route_add(const void *request, struct api_ctx *) {
	const struct gr_mpls_label_route_add_req *req = request;
	struct nexthop *nh;
	int ret;

	if (req->in_label > GR_MPLS_LABEL_MAX)
		return api_out(EINVAL, 0, NULL);

	nh = nexthop_lookup_id(req->nh_id);
	if (nh == NULL)
		return api_out(ENOENT, 0, NULL);
	if (nh->type != GR_NH_T_MPLS && nh->type != GR_NH_T_GROUP)
		return api_out(EINVAL, 0, NULL);

	ret = mpls_rib_insert(req->vrf_id, req->in_label, nh, req->origin, req->exist_ok);

	return api_out(-ret, 0, NULL);
}

static struct api_out label_route_del(const void *request, struct api_ctx *) {
	const struct gr_mpls_label_route_del_req *req = request;
	int ret;

	ret = mpls_rib_delete(req->vrf_id, req->in_label, req->missing_ok);

	return api_out(-ret, 0, NULL);
}

static struct api_out label_route_get(const void *request, struct api_ctx *) {
	const struct gr_mpls_label_route_get_req *req = request;
	struct gr_mpls_label_route *resp;
	const struct nexthop *nh;

	nh = mpls_fib_lookup(req->vrf_id, req->in_label);
	if (nh == NULL)
		return api_out(ENOENT, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->vrf_id = req->vrf_id;
	resp->in_label = req->in_label;
	resp->nh_id = nh->nh_id;
	resp->origin = nh->origin;

	return api_out(0, sizeof(*resp), resp);
}

struct label_list_ctx {
	struct api_ctx *ctx;
	uint16_t max_count;
	uint16_t count;
};

static int label_route_send(uint16_t vrf_id, uint32_t label, const struct nexthop *nh, void *priv) {
	struct label_list_ctx *lctx = priv;
	struct gr_mpls_label_route route;

	if (lctx->max_count != 0 && lctx->count >= lctx->max_count)
		return errno_set(EXFULL);

	route = (struct gr_mpls_label_route) {
		.vrf_id = vrf_id,
		.in_label = label,
		.nh_id = nh->nh_id,
		.origin = nh->origin,
	};

	api_send(lctx->ctx, sizeof(route), &route);
	lctx->count++;

	return 0;
}

static struct api_out label_route_list(const void *request, struct api_ctx *ctx) {
	const struct gr_mpls_label_route_list_req *req = request;
	struct label_list_ctx lctx;
	int ret;

	lctx = (struct label_list_ctx) {
		.ctx = ctx,
		.max_count = req->max_count,
	};

	ret = mpls_rib_iter(req->vrf_id, label_route_send, &lctx);
	if (ret == -EXFULL)
		ret = 0;

	return api_out(-ret, 0, NULL);
}

// label range reservation — simple linked list; small number of entries expected

struct label_range_entry {
	struct gr_mpls_label_range range;
	struct label_range_entry *next;
};

static struct label_range_entry *label_ranges;

static struct api_out label_range_add(const void *request, struct api_ctx *) {
	const struct gr_mpls_label_range_add_req *req = request;
	struct label_range_entry *e;

	if (req->start > req->end || req->end > GR_MPLS_LABEL_MAX)
		return api_out(EINVAL, 0, NULL);

	for (struct label_range_entry *ex = label_ranges; ex != NULL; ex = ex->next) {
		if (ex->range.vrf_id != req->vrf_id)
			continue;
		if (ex->range.start == req->start && ex->range.end == req->end) {
			if (!req->exist_ok)
				return api_out(EEXIST, 0, NULL);
			return api_out(0, 0, NULL);
		}
	}

	e = calloc(1, sizeof(*e));
	if (e == NULL)
		return api_out(ENOMEM, 0, NULL);

	e->range.vrf_id = req->vrf_id;
	e->range.start = req->start;
	e->range.end = req->end;
	e->range.origin = req->origin;
	e->next = label_ranges;
	label_ranges = e;

	return api_out(0, 0, NULL);
}

static struct api_out label_range_del(const void *request, struct api_ctx *) {
	const struct gr_mpls_label_range_del_req *req = request;
	struct label_range_entry **pp;

	pp = &label_ranges;

	while (*pp != NULL) {
		struct label_range_entry *e = *pp;
		if (e->range.vrf_id == req->vrf_id && e->range.start == req->start
		    && e->range.end == req->end) {
			*pp = e->next;
			free(e);
			return api_out(0, 0, NULL);
		}
		pp = &e->next;
	}

	if (!req->missing_ok)
		return api_out(ENOENT, 0, NULL);
	return api_out(0, 0, NULL);
}

static struct api_out label_range_list(const void *request, struct api_ctx *ctx) {
	const struct gr_mpls_label_range_list_req *req = request;

	for (struct label_range_entry *e = label_ranges; e != NULL; e = e->next) {
		if (req->vrf_id != 0 && e->range.vrf_id != req->vrf_id)
			continue;
		api_send(ctx, sizeof(e->range), &e->range);
	}

	return api_out(0, 0, NULL);
}

static struct module mpls_module = {
	.name = "mpls",
	.depends_on = "nexthop",
};

RTE_INIT(mpls_constructor) {
	module_register(&mpls_module);
	api_handler(GR_MPLS_LABEL_ROUTE_ADD, label_route_add);
	api_handler(GR_MPLS_LABEL_ROUTE_DEL, label_route_del);
	api_handler(GR_MPLS_LABEL_ROUTE_GET, label_route_get);
	api_handler(GR_MPLS_LABEL_ROUTE_LIST, label_route_list);
	event_serializer(GR_EVENT_MPLS_ROUTE_ADD, NULL);
	event_serializer(GR_EVENT_MPLS_ROUTE_DEL, NULL);
	api_handler(GR_MPLS_LABEL_RANGE_ADD, label_range_add);
	api_handler(GR_MPLS_LABEL_RANGE_DEL, label_range_del);
	api_handler(GR_MPLS_LABEL_RANGE_LIST, label_range_list);
}
