// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_api.h>
#include <gr_errno.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_module.h>
#include <gr_nh_control.h>
#include <gr_srv6.h>

#include <errno.h>
#include <string.h>

static void srv6_iface_nh_cleanup_nexthop(struct nexthop *nh) {
	struct iface *iface = NULL;

	if (nh->type != GR_NH_T_SR6_OUTPUT)
		return;

	// Iterate over all interfaces
	while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
		if (iface->mode == GR_IFACE_MODE_SRV6_XC) {
			if (iface->mode_data == nh->nh_id) {
				iface->mode_data = (uintptr_t)0;
				iface->mode_info = NULL;
			}
		}
	}
}

// Event handlers for cleanup
static void srv6_iface_nh_event_handler(uint32_t event, const void *obj) {
	switch (event) {
	case GR_EVENT_NEXTHOP_DELETE: {
		const struct nexthop *nh = obj;
		srv6_iface_nh_cleanup_nexthop((struct nexthop *)nh);
		break;
	}
	}
}

static struct gr_event_subscription srv6_iface_event_sub = {
	.callback = srv6_iface_nh_event_handler,
	.ev_count = 1,
	.ev_types = {GR_EVENT_NEXTHOP_DELETE},
};

static int srv6_l2_encap_mode_init(
	struct iface *iface,
	const void * /* api_info */
) {
	struct nexthop *nh = nexthop_lookup_by_id(iface->mode_data);
	if (nh == NULL)
		return -errno;
	iface->mode_info = nh;
	return 0;
}

static int srv6_l2_encap_mode_reconfig(
	struct iface *iface,
	uint64_t /* set_attrs */,
	const struct gr_iface *conf,
	const void * /* api_info */
) {
	struct nexthop *nh = nexthop_lookup_by_id(conf->mode_data);
	if (nh == NULL)
		return -errno;
	iface->mode_data = conf->mode_data;
	iface->mode_info = nh;
	return 0;
}

static struct iface_mode iface_mode_srv6_l2_encap = {
	.id = GR_IFACE_MODE_SRV6_XC,
	.init = srv6_l2_encap_mode_init,
	.reconfig = srv6_l2_encap_mode_reconfig,
};

RTE_INIT(srv6_iface_nh_constructor) {
	iface_mode_register(&iface_mode_srv6_l2_encap);
	gr_event_subscribe(&srv6_iface_event_sub);
}
