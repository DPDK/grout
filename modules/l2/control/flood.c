// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_event.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_module.h>

#include <errno.h>

static const struct flood_type_ops *flood_types[UINT_NUM_VALUES(gr_flood_type_t)];

static bool flood_type_valid(gr_flood_type_t type) {
	switch (type) {
	case GR_FLOOD_T_VTEP:
		return true;
	}
	return false;
}

void flood_type_register(const struct flood_type_ops *ops) {
	if (!flood_type_valid(ops->type))
		ABORT("invalid flood type %u", ops->type);
	if (flood_types[ops->type] != NULL)
		ABORT("flood type %u already registered", ops->type);
	flood_types[ops->type] = ops;
}

static struct api_out flood_add(const void *request, struct api_ctx *) {
	const struct gr_flood_add_req *req = request;
	const struct flood_type_ops *ops;
	int ret;

	ops = flood_types[req->entry.type];
	if (ops == NULL || ops->add == NULL)
		return api_out(EAFNOSUPPORT, 0, NULL);

	ret = ops->add(&req->entry, req->exist_ok);

	return api_out(-ret, 0, NULL);
}

static struct gr_api_handler flood_add_handler = {
	.name = "flood add",
	.request_type = GR_FLOOD_ADD,
	.callback = flood_add,
};

static struct api_out flood_del(const void *request, struct api_ctx *) {
	const struct gr_flood_del_req *req = request;
	const struct flood_type_ops *ops;
	int ret;

	ops = flood_types[req->entry.type];
	if (ops == NULL || ops->del == NULL)
		return api_out(EAFNOSUPPORT, 0, NULL);

	ret = ops->del(&req->entry, req->missing_ok);

	return api_out(-ret, 0, NULL);
}

static struct gr_api_handler flood_del_handler = {
	.name = "flood del",
	.request_type = GR_FLOOD_DEL,
	.callback = flood_del,
};

static struct api_out flood_list(const void *request, struct api_ctx *ctx) {
	const struct gr_flood_list_req *req = request;
	const struct flood_type_ops *ops;

	for (unsigned t = 0; t < ARRAY_DIM(flood_types); t++) {
		if (req->type != 0 && req->type != t)
			continue;
		ops = flood_types[t];
		if (ops == NULL || ops->list == NULL)
			continue;
		if (ops->list(req->vrf_id, ctx) < 0)
			return api_out(errno, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct gr_api_handler flood_list_handler = {
	.name = "flood list",
	.request_type = GR_FLOOD_LIST,
	.callback = flood_list,
};

static struct gr_event_serializer serializer = {
	.size = sizeof(struct gr_flood_entry),
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_FLOOD_ADD,
		GR_EVENT_FLOOD_DEL,
	},
};

RTE_INIT(flood_init) {
	gr_register_api_handler(&flood_add_handler);
	gr_register_api_handler(&flood_del_handler);
	gr_register_api_handler(&flood_list_handler);
	gr_event_register_serializer(&serializer);
}
