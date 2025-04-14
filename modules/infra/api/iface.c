// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_queue.h>
#include <gr_worker.h>

#include <rte_ethdev.h>
#include <rte_ether.h>

static void iface_to_api(struct gr_iface *to, const struct iface *from) {
	struct iface_type *type = iface_type_get(from->type);
	to->base = from->base;
	memccpy(to->name, from->name, 0, sizeof(to->name));
	type->to_api(to->info, from);
}

static struct api_out iface_add(const void *request, void **response) {
	const struct gr_infra_iface_add_req *req = request;
	struct gr_infra_iface_add_resp *resp;
	struct iface *iface;

	iface = iface_create(&req->iface, req->iface.info);
	if (iface == NULL)
		return api_out(errno, 0);

	if ((resp = malloc(sizeof(*resp))) == NULL) {
		iface_destroy(iface->id);
		return api_out(ENOMEM, 0);
	}

	resp->iface_id = iface->id;
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out iface_del(const void *request, void ** /*response*/) {
	const struct gr_infra_iface_del_req *req = request;
	struct iface *iface;
	int ret;

	// Loopback interfaces are special, and are deleted
	// when the last interface of a VRF is destroyed.
	if ((iface = iface_from_id(req->iface_id)) == NULL)
		return api_out(ENODEV, 0);

	if (iface->type == GR_IFACE_TYPE_LOOPBACK)
		return api_out(EINVAL, 0);

	ret = iface_destroy(req->iface_id);

	return api_out(-ret, 0);
}

static struct api_out iface_get(const void *request, void **response) {
	const struct gr_infra_iface_get_req *req = request;
	struct gr_infra_iface_get_resp *resp = NULL;
	struct iface *iface;

	if ((iface = iface_from_id(req->iface_id)) == NULL)
		return api_out(ENODEV, 0);

	if ((resp = malloc(sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);

	iface_to_api(&resp->iface, iface);
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out iface_list(const void *request, void **response) {
	const struct gr_infra_iface_list_req *req = request;
	struct gr_infra_iface_list_resp *resp = NULL;
	const struct iface *iface = NULL;
	uint16_t n_ifaces;
	size_t len;

	n_ifaces = ifaces_count(req->type);

	len = sizeof(*resp) + n_ifaces * sizeof(struct gr_iface);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	while ((iface = iface_next(req->type, iface)) != NULL)
		iface_to_api(&resp->ifaces[resp->n_ifaces++], iface);

	*response = resp;

	return api_out(0, len);
}

static struct api_out iface_set(const void *request, void ** /*response*/) {
	const struct gr_infra_iface_set_req *req = request;
	int ret;

	ret = iface_reconfig(req->iface.id, req->set_attrs, &req->iface, req->iface.info);
	if (ret < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct gr_api_handler iface_add_handler = {
	.name = "iface add",
	.request_type = GR_INFRA_IFACE_ADD,
	.callback = iface_add,
};
static struct gr_api_handler iface_del_handler = {
	.name = "iface del",
	.request_type = GR_INFRA_IFACE_DEL,
	.callback = iface_del,
};
static struct gr_api_handler iface_get_handler = {
	.name = "iface get",
	.request_type = GR_INFRA_IFACE_GET,
	.callback = iface_get,
};
static struct gr_api_handler iface_list_handler = {
	.name = "iface list",
	.request_type = GR_INFRA_IFACE_LIST,
	.callback = iface_list,
};
static struct gr_api_handler iface_set_handler = {
	.name = "iface set",
	.request_type = GR_INFRA_IFACE_SET,
	.callback = iface_set,
};

static int iface_event_serialize(const void *obj, void **buf) {
	struct gr_iface *api_iface = calloc(1, sizeof(*api_iface));
	if (api_iface == NULL)
		return errno_set(ENOMEM);

	iface_to_api(api_iface, obj);
	*buf = api_iface;

	return sizeof(*api_iface);
}

static struct gr_event_serializer iface_serializer = {
	.callback = iface_event_serialize,
	.ev_count = 5,
	.ev_types = {
		IFACE_EVENT_POST_ADD,
		IFACE_EVENT_PRE_REMOVE,
		IFACE_EVENT_POST_RECONFIG,
		IFACE_EVENT_STATUS_UP,
		IFACE_EVENT_STATUS_DOWN,
	},
};

RTE_INIT(infra_api_init) {
	gr_register_api_handler(&iface_add_handler);
	gr_register_api_handler(&iface_del_handler);
	gr_register_api_handler(&iface_get_handler);
	gr_register_api_handler(&iface_list_handler);
	gr_register_api_handler(&iface_set_handler);
	gr_event_register_serializer(&iface_serializer);
}
