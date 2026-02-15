// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_event.h>
#include <gr_l2_control.h>
#include <gr_rcu.h>
#include <gr_vrf.h>

#include <rte_ether.h>
#include <rte_hash.h>

static int bridge_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *,
	const void *api_info
) {
	struct iface_info_bridge *cur = iface_info_bridge(iface);
	const struct gr_iface_info_bridge *next = api_info;

	if (set_attrs & GR_BRIDGE_SET_MAC)
		iface_set_eth_addr(iface, &next->mac);
	if (set_attrs & GR_BRIDGE_SET_FLAGS)
		cur->flags = next->flags;
	if (set_attrs & GR_BRIDGE_SET_AGEING_TIME)
		cur->ageing_time = next->ageing_time ?: GR_BRIDGE_DEFAULT_AGEING;

	return 0;
}

static int bridge_attach_member(struct iface *bridge, struct iface *member) {
	struct iface_info_bridge *br = iface_info_bridge(bridge);

	switch (member->type) {
	case GR_IFACE_TYPE_PORT:
	case GR_IFACE_TYPE_VLAN:
	case GR_IFACE_TYPE_BOND:
		break;
	default:
		return errno_set(EMEDIUMTYPE);
	}

	for (unsigned i = 0; i < br->n_members; i++) {
		if (br->members[i] == member)
			return 0; // already a member
	}

	if (br->n_members == ARRAY_DIM(br->members))
		return errno_set(EUSERS);

	br->members[br->n_members++] = member;
	member->domain_id = bridge->id;
	member->vrf_id = GR_VRF_ID_UNDEF;
	member->mode = GR_IFACE_MODE_BRIDGE;

	return 0;
}

static int bridge_detach_member(struct iface *bridge, struct iface *member) {
	struct iface_info_bridge *br = iface_info_bridge(bridge);

	for (unsigned i = 0; i < br->n_members; i++) {
		if (br->members[i] == member) {
			unsigned last = br->n_members - 1;
			if (i < last)
				br->members[i] = br->members[last];
			br->n_members--;
			member->domain_id = GR_IFACE_ID_UNDEF;
			member->mode = GR_IFACE_MODE_VRF;
			fdb_purge_iface(member->id);
			break;
		}
	}

	return 0;
}

static int bridge_fini(struct iface *iface) {
	struct iface_info_bridge *bridge = iface_info_bridge(iface);

	for (unsigned i = 0; i < bridge->n_members; i++) {
		struct iface *member = bridge->members[i];
		member->vrf_id = vrf_default_get_or_create();
		if (member->vrf_id != GR_VRF_ID_UNDEF)
			vrf_incref(member->vrf_id);
		member->domain_id = GR_IFACE_ID_UNDEF;
		member->mode = GR_IFACE_MODE_VRF;
		gr_event_push(GR_EVENT_IFACE_POST_RECONFIG, member);
	}

	fdb_purge_bridge(iface->id);

	return 0;
}

static int bridge_init(struct iface *iface, const void *api_info) {
	int ret;

	iface->domain_id = iface->id; // for convenience, bridges are in their own domain

	ret = bridge_reconfig(iface, IFACE_SET_ALL, NULL, api_info);
	if (ret < 0) {
		bridge_fini(iface);
		errno = -ret;
	}

	return ret;
}

static int bridge_get_eth_addr(const struct iface *iface, struct rte_ether_addr *mac) {
	const struct iface_info_bridge *bridge = iface_info_bridge(iface);
	*mac = bridge->mac;
	return 0;
}

static int bridge_set_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	struct iface_info_bridge *bridge = iface_info_bridge(iface);

	if (rte_is_zero_ether_addr(mac)) {
		rte_eth_random_addr(bridge->mac.addr_bytes);
	} else {
		bridge->mac = *mac;
	}

	return 0;
}

static void bridge_to_api(void *info, const struct iface *iface) {
	const struct iface_info_bridge *bridge = iface_info_bridge(iface);
	struct gr_iface_info_bridge *api = info;

	api->ageing_time = bridge->ageing_time;
	api->flags = bridge->flags;
	api->mac = bridge->mac;
	api->n_members = bridge->n_members;
	for (unsigned i = 0; i < bridge->n_members; i++)
		api->members[i] = bridge->members[i]->id;
}

static struct iface_type iface_type_bridge = {
	.id = GR_IFACE_TYPE_BRIDGE,
	.pub_size = sizeof(struct gr_iface_info_bridge),
	.priv_size = sizeof(struct iface_info_bridge),
	.init = bridge_init,
	.reconfig = bridge_reconfig,
	.fini = bridge_fini,
	.attach_domain = bridge_attach_member,
	.detach_domain = bridge_detach_member,
	.get_eth_addr = bridge_get_eth_addr,
	.set_eth_addr = bridge_set_eth_addr,
	.to_api = bridge_to_api,
};

RTE_INIT(bridge_constructor) {
	iface_type_register(&iface_type_bridge);
}
