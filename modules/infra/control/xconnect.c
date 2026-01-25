// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "gr_l2.h"

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_module.h>

static struct api_out l2_mode_set(const void *request, void ** /* response */) {
	const struct gr_l2_iface_mode_req *req = request;
	struct iface *iface;

	iface = iface_from_id(req->iface_id);
	if (iface == NULL)
		return api_out(errno, 0);

	// Clean all L3 related info
	if (req->mode != GR_IFACE_MODE_VRF)
		gr_event_push(GR_EVENT_IFACE_STATUS_DOWN, iface);

	iface->mode = req->mode;
	iface->bridge_domain = req->domain_id;

	if (req->mode == GR_IFACE_MODE_VRF)
		gr_event_push(GR_EVENT_IFACE_STATUS_UP, iface);

	return api_out(0, 0);
}

static struct gr_api_handler l2_mode_set_handler = {
	.name = "l2 xconnect set",
	.request_type = GR_L2_MODE_SET,
	.callback = l2_mode_set,
};

RTE_INIT(l2_constructor) {
	gr_register_api_handler(&l2_mode_set_handler);
}
