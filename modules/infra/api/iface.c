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

static struct gr_iface *iface_to_api(const struct iface *priv) {
	const struct iface_type *type = iface_type_get(priv->type);
	assert(type != NULL);
	struct gr_iface *pub = malloc(sizeof(*pub) + type->pub_size);
	if (pub == NULL)
		return errno_set_null(ENOMEM);
	pub->base = priv->base;
	memccpy(pub->name, priv->name, 0, sizeof(pub->name));
	type->to_api(pub->info, priv);
	return pub;
}

static struct api_out iface_add(const void *request, struct api_ctx *) {
	const struct gr_infra_iface_add_req *req = request;
	struct gr_infra_iface_add_resp *resp;
	struct iface *iface;

	iface = iface_create(&req->iface, req->iface.info);
	if (iface == NULL)
		return api_out(errno, 0, NULL);

	if ((resp = malloc(sizeof(*resp))) == NULL) {
		iface_destroy(iface->id);
		return api_out(ENOMEM, 0, NULL);
	}

	resp->iface_id = iface->id;

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out iface_del(const void *request, struct api_ctx *) {
	const struct gr_infra_iface_del_req *req = request;
	struct iface *iface;
	int ret;

	// Loopback interfaces are special, and are deleted
	// when the last interface of a VRF is destroyed.
	if ((iface = iface_from_id(req->iface_id)) == NULL)
		return api_out(ENODEV, 0, NULL);

	if (iface->type == GR_IFACE_TYPE_LOOPBACK)
		return api_out(EINVAL, 0, NULL);

	ret = iface_destroy(req->iface_id);

	return api_out(-ret, 0, NULL);
}

static struct api_out iface_get(const void *request, struct api_ctx *) {
	const struct gr_infra_iface_get_req *req = request;
	const struct iface_type *type = NULL;
	const struct iface *priv = NULL;
	struct gr_iface *pub = NULL;

	if (req->iface_id != GR_IFACE_ID_UNDEF) {
		if ((priv = iface_from_id(req->iface_id)) == NULL)
			return api_out(ENODEV, 0, NULL);
	} else {
		while ((priv = iface_next(GR_IFACE_TYPE_UNDEF, priv)) != NULL) {
			if (strncmp(priv->name, req->name, sizeof(req->name)) == 0)
				break;
		}
		if (priv == NULL)
			return api_out(ENODEV, 0, NULL);
	}

	type = iface_type_get(priv->type);
	assert(type != NULL);

	pub = iface_to_api(priv);
	if (pub == NULL)
		return api_out(errno, 0, NULL);

	return api_out(0, sizeof(*pub) + type->pub_size, pub);
}

static struct api_out iface_list(const void *request, struct api_ctx *ctx) {
	const struct gr_infra_iface_list_req *req = request;
	const struct iface *iface = NULL;
	int ret = 0;

	while ((iface = iface_next(req->type, iface)) != NULL) {
		const struct iface_type *type = iface_type_get(iface->type);
		struct gr_iface *pub = iface_to_api(iface);
		assert(type != NULL);
		if (pub == NULL) {
			ret = errno;
			goto out;
		}
		api_send(ctx, sizeof(*pub) + type->pub_size, pub);
		free(pub);
	}

out:
	return api_out(ret, 0, NULL);
}

static struct api_out iface_set(const void *request, struct api_ctx *) {
	const struct gr_infra_iface_set_req *req = request;
	int ret;

	ret = iface_reconfig(req->iface.id, req->set_attrs, &req->iface, req->iface.info);
	if (ret < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
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
	struct gr_iface *api_iface = iface_to_api(obj);
	if (api_iface == NULL)
		return errno_set(ENOMEM);

	*buf = api_iface;

	const struct iface_type *type = iface_type_get(api_iface->type);
	assert(type != NULL);

	return sizeof(*api_iface) + type->pub_size;
}

static struct gr_event_serializer iface_serializer = {
	.callback = iface_event_serialize,
	.ev_count = 5,
	.ev_types = {
		GR_EVENT_IFACE_POST_ADD,
		GR_EVENT_IFACE_PRE_REMOVE,
		GR_EVENT_IFACE_POST_RECONFIG,
		GR_EVENT_IFACE_STATUS_UP,
		GR_EVENT_IFACE_STATUS_DOWN,
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
