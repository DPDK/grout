// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include <gr_event.h>
#include <gr_iface.h>
#include <gr_ip6.h>
#include <gr_net_types.h>
#include <gr_netlink.h>

#include <net/if.h>

static void addr_add_del_cb(uint32_t event, const void *obj) {
	struct iface *vrf_iface;
	struct iface *iface;
	uint16_t iface_id;
	bool add = false;
	const void *addr;
	size_t addr_len;

	switch (event) {
	case GR_EVENT_IP6_ADDR_ADD:
		add = true;
		// fallthrough
	case GR_EVENT_IP6_ADDR_DEL: {
		const struct gr_ip6_ifaddr *ifa6 = obj;

		iface_id = ifa6->iface_id;
		addr = &ifa6->addr.ip;
		addr_len = sizeof(ifa6->addr.ip);
		break;
	}
	default:
		return;
	}

	if ((iface = iface_from_id(iface_id)) == NULL)
		return;

	if ((vrf_iface = get_vrf_iface(iface->vrf_id)) == NULL)
		return;

	netlink_add_del_addr(vrf_iface->name, addr, addr_len, add);
}

static struct gr_event_subscription addr_add_del_subscription = {
	.callback = addr_add_del_cb,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IP6_ADDR_ADD,
		GR_EVENT_IP6_ADDR_DEL,
	}
};

RTE_INIT(netlink_ip6_constructor) {
	gr_event_subscribe(&addr_add_del_subscription);
}
