// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_api.h>
#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_module.h>

#include <stdlib.h>

static struct api_out iface_security_set(const void *request, struct api_ctx *) {
	const struct gr_l2_iface_security_req *req = request;
	const struct iface *iface;

	iface = iface_from_id(req->iface_id);
	if (iface == NULL)
		return api_out(ENOENT, 0, NULL);

	if (iface->mode != GR_IFACE_MODE_BRIDGE)
		return api_out(EINVAL, 0, NULL);

	if (req->iface_id >= L2_MAX_IFACES)
		return api_out(ERANGE, 0, NULL);

	l2_iface_security[req->iface_id].max_macs = req->max_macs;
	l2_iface_security[req->iface_id].shutdown_on_violation = req->shutdown_on_violation;

	return api_out(0, 0, NULL);
}

static struct api_out iface_security_get(const void *request, struct api_ctx *) {
	const struct gr_l2_iface_security_req *req = request;
	struct gr_l2_iface_security_status *resp;
	const struct iface *iface;

	iface = iface_from_id(req->iface_id);
	if (iface == NULL)
		return api_out(ENOENT, 0, NULL);

	if (iface->mode != GR_IFACE_MODE_BRIDGE)
		return api_out(EINVAL, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = iface->domain_id;
	resp->iface_id = req->iface_id;
	resp->max_macs = iface_get_max_macs(req->iface_id);
	resp->current_macs = iface_get_total_macs(req->iface_id);
	resp->shutdown_on_violation = iface_get_shutdown_on_violation(req->iface_id);
	resp->is_shutdown = iface_is_shutdown(req->iface_id);

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out iface_security_reenable(const void *request, struct api_ctx *) {
	const struct gr_l2_iface_security_reenable_req *req = request;
	const struct iface *iface;

	iface = iface_from_id(req->iface_id);
	if (iface == NULL)
		return api_out(ENOENT, 0, NULL);

	if (iface->mode != GR_IFACE_MODE_BRIDGE)
		return api_out(EINVAL, 0, NULL);

	if (req->iface_id < L2_MAX_IFACES && l2_iface_security[req->iface_id].is_shutdown) {
		l2_iface_security[req->iface_id].is_shutdown = false;
		LOG(INFO, "iface %s re-enabled after port security violation", iface->name);
	}

	return api_out(0, 0, NULL);
}

static struct gr_api_handler iface_security_set_handler = {
	.name = "iface security set",
	.request_type = GR_L2_IFACE_SECURITY_SET,
	.callback = iface_security_set,
};

static struct gr_api_handler iface_security_get_handler = {
	.name = "iface security get",
	.request_type = GR_L2_IFACE_SECURITY_GET,
	.callback = iface_security_get,
};

static struct gr_api_handler iface_security_reenable_handler = {
	.name = "iface security reenable",
	.request_type = GR_L2_IFACE_SECURITY_REENABLE,
	.callback = iface_security_reenable,
};

RTE_INIT(iface_security_constructor) {
	gr_register_api_handler(&iface_security_set_handler);
	gr_register_api_handler(&iface_security_get_handler);
	gr_register_api_handler(&iface_security_reenable_handler);
}
