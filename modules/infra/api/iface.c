// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_infra.h"

#include <br_api.h>
#include <br_control.h>
#include <br_iface.h>
#include <br_log.h>
#include <br_queue.h>
#include <br_worker.h>

#include <rte_ethdev.h>
#include <rte_ether.h>

static void iface_to_api(struct br_iface *to, const struct iface *from) {
	struct iface_type *type = iface_type_get(from->type_id);
	to->id = from->id;
	to->type = from->type_id;
	to->flags = from->flags;
	to->state = from->state;
	to->mtu = from->mtu;
	to->vrf_id = from->vrf_id;
	memccpy(to->name, from->name, 0, sizeof(to->name));
	type->to_api(to->info, from);
}

static struct api_out iface_add(const void *request, void **response) {
	const struct br_infra_iface_add_req *req = request;
	struct br_infra_iface_add_resp *resp;
	struct iface *iface;

	iface = iface_create(
		req->iface.type,
		req->iface.flags,
		req->iface.mtu,
		req->iface.vrf_id,
		req->iface.name,
		req->iface.info
	);
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

static struct api_out iface_del(const void *request, void **response) {
	const struct br_infra_iface_del_req *req = request;
	int ret;

	(void)response;

	ret = iface_destroy(req->iface_id);

	return api_out(-ret, 0);
}

static struct api_out iface_get(const void *request, void **response) {
	const struct br_infra_iface_get_req *req = request;
	struct br_infra_iface_get_resp *resp = NULL;
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
	const struct br_infra_iface_list_req *req = request;
	struct br_infra_iface_list_resp *resp = NULL;
	const struct iface *iface = NULL;
	uint16_t n_ifaces;
	size_t len;

	n_ifaces = ifaces_count(req->type);

	len = sizeof(*resp) + n_ifaces * sizeof(struct br_iface);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	while ((iface = iface_next(req->type, iface)) != NULL)
		iface_to_api(&resp->ifaces[resp->n_ifaces++], iface);

	*response = resp;

	return api_out(0, len);
}

static struct api_out iface_set(const void *request, void **response) {
	const struct br_infra_iface_set_req *req = request;
	int ret;

	(void)response;

	ret = iface_reconfig(
		req->iface.id,
		req->set_attrs,
		req->iface.flags,
		req->iface.mtu,
		req->iface.vrf_id,
		req->iface.name,
		req->iface.info
	);
	if (ret < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct br_api_handler iface_add_handler = {
	.name = "iface add",
	.request_type = BR_INFRA_IFACE_ADD,
	.callback = iface_add,
};
static struct br_api_handler iface_del_handler = {
	.name = "iface del",
	.request_type = BR_INFRA_IFACE_DEL,
	.callback = iface_del,
};
static struct br_api_handler iface_get_handler = {
	.name = "iface get",
	.request_type = BR_INFRA_IFACE_GET,
	.callback = iface_get,
};
static struct br_api_handler iface_list_handler = {
	.name = "iface list",
	.request_type = BR_INFRA_IFACE_LIST,
	.callback = iface_list,
};
static struct br_api_handler iface_set_handler = {
	.name = "iface set",
	.request_type = BR_INFRA_IFACE_SET,
	.callback = iface_set,
};

RTE_INIT(infra_api_init) {
	br_register_api_handler(&iface_add_handler);
	br_register_api_handler(&iface_del_handler);
	br_register_api_handler(&iface_get_handler);
	br_register_api_handler(&iface_list_handler);
	br_register_api_handler(&iface_set_handler);
}
