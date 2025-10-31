// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_bond.h>
#include <gr_event.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_rcu.h>

#include <rte_ether.h>

static int
bond_all_member_add_mac(const struct iface_info_bond *bond, const struct rte_ether_addr *mac) {
	const struct iface *member;

	for (uint8_t i = 0; i < bond->n_members; i++) {
		member = bond->members[i];
		if (iface_add_eth_addr(member->id, mac) < 0)
			return errno_set(errno);
	}

	return 0;
}

static int
bond_all_member_del_mac(const struct iface_info_bond *bond, const struct rte_ether_addr *mac) {
	const struct iface *member;

	for (uint8_t i = 0; i < bond->n_members; i++) {
		member = bond->members[i];
		if (iface_del_eth_addr(member->id, mac) < 0 && errno != ENOENT)
			return errno_set(errno);
	}

	return 0;
}

static int bond_mac_add(struct iface *iface, const struct rte_ether_addr *mac) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	int ret;

	// Add MAC address to all member ports
	if ((ret = bond_all_member_add_mac(bond, mac)) < 0)
		return ret;

	gr_vec_add(bond->extra_macs, *mac);

	return 0;
}

static int bond_mac_del(struct iface *iface, const struct rte_ether_addr *mac) {
	struct iface_info_bond *bond = iface_info_bond(iface);

	// Remove MAC address from all member ports
	bond_all_member_del_mac(bond, mac);

	for (unsigned i = 0; i < gr_vec_len(bond->extra_macs); i++) {
		if (rte_is_same_ether_addr(&bond->extra_macs[i], mac)) {
			gr_vec_del(bond->extra_macs, i);
			break;
		}
	}

	return 0;
}

static int bond_mac_set(struct iface *iface, const struct rte_ether_addr *mac) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	int ret;

	if (!rte_is_zero_ether_addr(&bond->mac)) {
		if ((ret = bond_all_member_del_mac(bond, &bond->mac)) < 0)
			return ret;
	}
	if ((ret = bond_all_member_add_mac(bond, mac)) < 0)
		return ret;

	bond->mac = *mac;

	return 0;
}

static int bond_mac_get(const struct iface *iface, struct rte_ether_addr *mac) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	*mac = bond->mac;
	return 0;
}

static int bond_mtu_set(struct iface *iface, uint16_t mtu) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	const struct iface *member;
	int ret;

	for (uint8_t i = 0; i < bond->n_members; i++) {
		member = bond->members[i];
		if (mtu == 0 && member->mtu != 0) {
			mtu = member->mtu;
		} else {
			if ((ret = iface_set_mtu(member->id, mtu)) < 0)
				return ret;
		}
	}

	iface->mtu = mtu;

	return 0;
}

static int bond_all_members_set_flag(
	struct iface *iface,
	gr_iface_flags_t flag,
	bool enabled,
	int (*func)(uint16_t, bool)
) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	const struct iface *member;
	int ret;

	for (uint8_t i = 0; i < bond->n_members; i++) {
		member = bond->members[i];
		if ((ret = func(member->id, enabled)) < 0)
			return ret;
	}

	if (enabled)
		iface->flags |= flag;
	else
		iface->flags &= ~flag;

	return 0;
}

static int bond_promisc_set(struct iface *iface, bool enabled) {
	return bond_all_members_set_flag(iface, GR_IFACE_F_PROMISC, enabled, iface_set_promisc);
}

static int bond_allmulti_set(struct iface *iface, bool enabled) {
	return bond_all_members_set_flag(iface, GR_IFACE_F_ALLMULTI, enabled, iface_set_allmulti);
}

static int bond_vlan_add(struct iface *iface, uint16_t vlan_id) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	const struct iface *member;
	int ret;

	for (uint8_t i = 0; i < bond->n_members; i++) {
		member = bond->members[i];
		if ((ret = iface_add_vlan(member->id, vlan_id)) < 0)
			return ret;
	}

	return 0;
}

static int bond_vlan_del(struct iface *iface, uint16_t vlan_id) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	const struct iface *member;
	int ret;

	for (uint8_t i = 0; i < bond->n_members; i++) {
		member = bond->members[i];
		if ((ret = iface_del_vlan(member->id, vlan_id)) < 0)
			return ret;
	}

	return 0;
}

static int bond_init_new_members(const struct iface *iface, const struct gr_iface_info_bond *new) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	struct iface_info_port *port;

	for (uint8_t i = 0; i < new->n_members; i++) {
		struct iface *member = iface_from_id(new->member_iface_ids[i]);
		if (member == NULL)
			return errno_set(errno);

		if (member->type != GR_IFACE_TYPE_PORT)
			return errno_set(EMEDIUMTYPE);

		for (uint8_t j = 0; j < bond->n_members; j++) {
			if (bond->members[j]->id == member->id)
				goto skip;
		}

		LOG(DEBUG, "adding %s to bond %s", member->name, iface->name);
		port = iface_info_port(member);
		port->bond_iface_id = iface->id;
skip:;
	}

	return 0;
}

static void bond_fini_old_members(const struct iface *iface, const struct gr_iface_info_bond *new) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	struct iface_info_port *port;

	for (uint8_t i = 0; i < bond->n_members; i++) {
		const struct iface *member = bond->members[i];

		for (uint8_t j = 0; j < new->n_members; j++) {
			if (new->member_iface_ids[j] == member->id)
				goto skip;
		}

		LOG(DEBUG, "removing %s from bond %s", member->name, iface->name);
		gr_vec_foreach_ref (struct rte_ether_addr *mac, bond->extra_macs) {
			if (iface_del_eth_addr(member->id, mac) < 0 && errno != ENOENT) {
				LOG(WARNING,
				    "failed to unconfigure mac address on member %s: %s",
				    member->name,
				    strerror(errno));
			}
		}
		if (iface_del_eth_addr(member->id, &bond->mac) < 0 && errno != ENOENT) {
			LOG(WARNING,
			    "failed to unconfigure mac address on member %s: %s",
			    member->name,
			    strerror(errno));
		}

		port = iface_info_port(member);
		port->bond_iface_id = GR_IFACE_ID_UNDEF;
skip:;
	}
}

static void bond_update_active_members(struct iface *iface) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	struct iface *member;

	switch (bond->mode) {
	case GR_BOND_MODE_ACTIVE_BACKUP:
		uint8_t active_member = UINT8_MAX;
		for (uint8_t i = 0; i < bond->n_members; i++) {
			member = bond->members[i];
			if ((member->flags & GR_IFACE_F_UP) && (member->state & GR_IFACE_S_RUNNING)
			    && (active_member == UINT8_MAX || i == bond->primary_member)) {
				active_member = i;
			}
		}
		bond->n_active_members = 0;
		for (uint8_t i = 0; i < bond->n_members; i++) {
			member = bond->members[i];
			if (i == active_member) {
				bond->n_active_members = 1;
				bond->active_members[0] = member;
				LOG(INFO,
				    "bond %s active member is now %s",
				    iface->name,
				    member->name);
				break;
			}
		}
		bond->active_member = active_member;
		break;
	}
	if (bond->n_active_members > 0)
		iface->state |= GR_IFACE_S_RUNNING;
	else
		iface->state &= ~GR_IFACE_S_RUNNING;
}

static int bond_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *,
	const void *api_info
) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	const struct gr_iface_info_bond *api = api_info;

	if (set_attrs & GR_BOND_SET_MODE)
		bond->mode = api->mode;

	if (set_attrs & GR_BOND_SET_PRIMARY) {
		uint8_t n_members = (set_attrs & GR_BOND_SET_MEMBERS) ?
			api->n_members :
			bond->n_members;

		if (api->primary_member >= n_members)
			return errno_set(ERANGE);

		bond->primary_member = api->primary_member;
	}

	if (set_attrs & GR_BOND_SET_MEMBERS) {
		if (api->n_members > ARRAY_DIM(bond->members))
			return errno_set(ERANGE);

		if (bond_init_new_members(iface, api) < 0)
			return errno_set(errno);

		bond_fini_old_members(iface, api);

		for (uint8_t i = 0; i < api->n_members; i++)
			bond->members[i] = iface_from_id(api->member_iface_ids[i]);
		bond->n_members = api->n_members;
	}

	if (set_attrs & (GR_BOND_SET_MAC | GR_BOND_SET_MEMBERS | GR_BOND_SET_PRIMARY)) {
		struct rte_ether_addr mac;
		if (rte_is_zero_ether_addr(&api->mac)) {
			if (iface_get_eth_addr(bond->members[bond->primary_member]->id, &mac) < 0)
				return errno_set(errno);
		} else {
			mac = api->mac;
		}
		if (bond_mac_set(iface, &mac) < 0)
			return errno_set(errno);
		bond->mac = mac;
	}

	if (set_attrs & (GR_BOND_SET_MEMBERS | GR_BOND_SET_PRIMARY))
		bond_update_active_members(iface);

	return 0;
}

static int bond_init(struct iface *iface, const void *api_info) {
	struct gr_iface conf = {.base = iface->base};
	return bond_reconfig(iface, IFACE_SET_ALL, &conf, api_info);
}

static int bond_fini(struct iface *iface) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	struct gr_iface_info_bond zero = {.n_members = 0};
	bond_fini_old_members(iface, &zero);
	gr_vec_free(bond->extra_macs);
	return 0;
}

static void bond_to_api(void *info, const struct iface *iface) {
	const struct iface_info_bond *bond = iface_info_bond(iface);
	struct gr_iface_info_bond *api = info;

	api->mode = bond->mode;
	api->mac = bond->mac;
	api->n_members = bond->n_members;
	api->primary_member = bond->primary_member;
	for (uint8_t i = 0; i < bond->n_members; i++)
		api->member_iface_ids[i] = bond->members[i]->id;
}

static struct iface_type iface_type_bond = {
	.id = GR_IFACE_TYPE_BOND,
	.name = "bond",
	.pub_size = sizeof(struct gr_iface_info_bond),
	.priv_size = sizeof(struct iface_info_bond),
	.init = bond_init,
	.reconfig = bond_reconfig,
	.fini = bond_fini,
	.set_eth_addr = bond_mac_set,
	.get_eth_addr = bond_mac_get,
	.add_eth_addr = bond_mac_add,
	.del_eth_addr = bond_mac_del,
	.set_mtu = bond_mtu_set,
	.set_promisc = bond_promisc_set,
	.set_allmulti = bond_allmulti_set,
	.add_vlan = bond_vlan_add,
	.del_vlan = bond_vlan_del,
	.to_api = bond_to_api,
};

static void bond_event(uint32_t, const void *obj) {
	const struct iface_info_port *port;
	const struct iface *iface = obj;
	struct iface *b;

	if (iface->type != GR_IFACE_TYPE_PORT)
		return;

	port = iface_info_port(iface);
	if (port->bond_iface_id == GR_IFACE_ID_UNDEF)
		return;

	b = iface_from_id(port->bond_iface_id);
	assert(b != NULL);
	assert(b->type == GR_IFACE_TYPE_BOND);

	bond_update_active_members(b);

	if (b->state & GR_IFACE_S_RUNNING && b->flags & GR_IFACE_F_UP)
		gr_event_push(GR_EVENT_IFACE_STATUS_UP, b);
	else
		gr_event_push(GR_EVENT_IFACE_STATUS_DOWN, b);
}

static struct gr_event_subscription bond_event_handler = {
	.callback = bond_event,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IFACE_STATUS_UP,
		GR_EVENT_IFACE_STATUS_DOWN,
	},
};

RTE_INIT(bond_constructor) {
	iface_type_register(&iface_type_bond);
	gr_event_subscribe(&bond_event_handler);
}
