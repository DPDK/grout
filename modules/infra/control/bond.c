// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_bond.h>
#include <gr_eth.h>
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
		member = bond->members[i].iface;
		if (iface_add_eth_addr(member->id, mac) < 0)
			return errno_set(errno);
	}

	return 0;
}

static int
bond_all_member_del_mac(const struct iface_info_bond *bond, const struct rte_ether_addr *mac) {
	const struct iface *member;

	for (uint8_t i = 0; i < bond->n_members; i++) {
		member = bond->members[i].iface;
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
	const struct bond_member *member;
	int ret;

	if (mtu == 0 && bond->primary_member < bond->n_members) {
		// use primary member MTU
		member = &bond->members[bond->primary_member];
		mtu = member->iface->mtu;
	}
	// make sure every member has the same MTU
	for (uint8_t i = 0; i < bond->n_members; i++) {
		member = &bond->members[i];
		if (member->iface->mtu == mtu)
			continue;
		if ((ret = iface_set_mtu(member->iface->id, mtu)) < 0)
			return ret;
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
		member = bond->members[i].iface;
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

static int bond_init_new_members(const struct iface *iface, const struct gr_iface_info_bond *new) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	struct iface_info_port *port;

	for (uint8_t i = 0; i < new->n_members; i++) {
		struct iface *member = iface_from_id(new->members[i].iface_id);
		if (member == NULL)
			return errno_set(errno);

		if (member->type != GR_IFACE_TYPE_PORT)
			return errno_set(EMEDIUMTYPE);

		for (uint8_t j = 0; j < bond->n_members; j++) {
			if (bond->members[j].iface->id == member->id)
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
		const struct iface *member = bond->members[i].iface;

		for (uint8_t j = 0; j < new->n_members; j++) {
			if (new->members[j].iface_id == member->id)
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
		memset(&bond->members[i], 0, sizeof(bond->members[i]));
skip:;
	}
}

void bond_update_active_members(struct iface *iface) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	const struct iface *member;
	uint8_t *active_ids = NULL;
	uint32_t speed = 0;

	switch (bond->mode) {
	case GR_BOND_MODE_ACTIVE_BACKUP:
		uint8_t active_member = UINT8_MAX;
		for (uint8_t i = 0; i < bond->n_members; i++) {
			member = bond->members[i].iface;
			if ((member->flags & GR_IFACE_F_UP) && (member->state & GR_IFACE_S_RUNNING)
			    && (active_member == UINT8_MAX || i == bond->primary_member)) {
				active_member = i;
			}
		}
		for (uint8_t i = 0; i < bond->n_members; i++) {
			member = bond->members[i].iface;
			if (i == active_member) {
				speed = member->speed;
				gr_vec_add(active_ids, i);
				LOG(INFO,
				    "bond %s active member is now %s",
				    iface->name,
				    member->name);
				break;
			}
		}
		bond->active_member = active_member;
		break;
	case GR_BOND_MODE_LACP:
		for (uint8_t i = 0; i < bond->n_members; i++) {
			struct bond_member *member = &bond->members[i];

			// The port_number must *never* be zero,
			// otherwise some switches reject the LACP packets.
			// Use a 1-based port_number.
			member->local.port_number = rte_cpu_to_be_16(i + 1);
			member->local.port_priority = RTE_BE16(0x8000);
			member->local.system_priority = RTE_BE16(0x8000);
			member->local.system_mac = bond->mac;
			// Key based on port speed (in Mb/s): simplified encoding for aggregation
			// Ports with same speed can aggregate together
			member->local.key = rte_cpu_to_be_16(member->iface->speed);
			if (member->last_rx == 0) {
				member->local.state = LACP_STATE_ACTIVE | LACP_STATE_AGGREGATABLE
					| LACP_STATE_FAST | LACP_STATE_DEFAULTED
					| LACP_STATE_EXPIRED;
				member->active = false;
				member->need_to_transmit = true;
				member->next_tx = 0;
				LOG(DEBUG,
				    "bond %s member %s reset local state",
				    iface->name,
				    member->iface->name);
			}

			// Add to active members if link is up and LACP member is valid
			if ((member->iface->flags & GR_IFACE_F_UP)
			    && (member->iface->state & GR_IFACE_S_RUNNING) && member->active) {
				LOG(DEBUG,
				    "bond %s member %s active",
				    iface->name,
				    member->iface->name);
				gr_vec_add(active_ids, i);
				if (member->iface->speed != RTE_ETH_SPEED_NUM_UNKNOWN)
					speed += member->iface->speed;
			}
		}
		break;
	}

	if (speed != 0)
		iface->speed = speed;
	else
		iface->speed = RTE_ETH_SPEED_NUM_UNKNOWN;

	if (gr_vec_len(active_ids) > 0) {
		for (unsigned i = 0; i < ARRAY_DIM(bond->redirection_table); i++) {
			bond->redirection_table[i] = active_ids[i % gr_vec_len(active_ids)];
		}
		if (!(iface->state & GR_IFACE_S_RUNNING)) {
			iface->state |= GR_IFACE_S_RUNNING;
			if (iface->flags & GR_IFACE_F_UP) {
				gr_event_push(GR_EVENT_IFACE_STATUS_UP, iface);
			}
		}
	} else {
		memset(bond->redirection_table, UINT8_MAX, sizeof(bond->redirection_table));
		if (iface->state & GR_IFACE_S_RUNNING) {
			iface->state &= ~GR_IFACE_S_RUNNING;
			gr_event_push(GR_EVENT_IFACE_STATUS_DOWN, iface);
		}
	}

	gr_vec_free(active_ids);
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

	if (set_attrs & GR_BOND_SET_ALGO)
		bond->algo = api->algo ?: GR_BOND_ALGO_RSS;

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
			bond->members[i].iface = iface_from_id(api->members[i].iface_id);
		bond->n_members = api->n_members;
	}

	if (set_attrs & (GR_BOND_SET_MAC | GR_BOND_SET_MEMBERS | GR_BOND_SET_PRIMARY)) {
		struct rte_ether_addr mac;
		if (rte_is_zero_ether_addr(&api->mac)) {
			const struct iface *primary = bond->members[bond->primary_member].iface;
			if (iface_get_eth_addr(primary->id, &mac) < 0)
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
	api->algo = bond->algo;
	api->mac = bond->mac;
	api->n_members = bond->n_members;
	api->primary_member = bond->primary_member;
	for (uint8_t i = 0; i < bond->n_members; i++) {
		api->members[i].iface_id = bond->members[i].iface->id;
		switch (bond->mode) {
		case GR_BOND_MODE_ACTIVE_BACKUP:
			api->members[i].active = i == bond->active_member;
			break;
		case GR_BOND_MODE_LACP:
			api->members[i].active = bond->members[i].active;
			break;
		}
	}
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
	if (b == NULL)
		return;
	assert(b->type == GR_IFACE_TYPE_BOND);

	bond_update_active_members(b);
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
