// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_config.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_module.h>
#include <gr_nh_control.h>
#include <gr_rcu.h>
#include <gr_string.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_malloc.h>

#include <errno.h>
#include <string.h>
#include <sys/queue.h>
#include <vrf_priv.h>
#include <wchar.h>

static STAILQ_HEAD(, iface_type) types = STAILQ_HEAD_INITIALIZER(types);

struct iface_stats iface_stats[MAX_IFACES][RTE_MAX_LCORE];

const struct iface_type *iface_type_get(gr_iface_type_t type_id) {
	struct iface_type *t;
	STAILQ_FOREACH (t, &types, next)
		if (t->id == type_id)
			return t;
	errno = ENODEV;
	return NULL;
}

void iface_type_register(struct iface_type *type) {
	if (iface_type_get(type->id) != NULL)
		ABORT("duplicate iface type id: %u", type->id);
	if (type->id >= GR_IFACE_TYPE_COUNT)
		ABORT("invalid iface type id: %u", type->id);
	STAILQ_INSERT_TAIL(&types, type, next);
}

#define IFACE_ID_FIRST GR_IFACE_ID_UNDEF + 1

// the first slot is wasted by GR_IFACE_ID_UNDEF
static struct iface **ifaces;

// Reserve a specific interface id.
// Returns 0 on success, -errno on failure.
static int reserve_ifid(uint16_t ifid) {
	if (ifid >= MAX_IFACES)
		return errno_set(EINVAL);

	if (ifaces[ifid] == NULL)
		return 0;

	return errno_set(EBUSY);
}

// The slot 1 to 255 are reserved for gr_loopback
static int next_ifid(uint16_t *ifid) {
	for (uint16_t i = GR_MAX_VRFS; i < MAX_IFACES; i++) {
		if (reserve_ifid(i) < 0)
			continue;

		*ifid = i;
		return 0;
	}

	return errno_set(ENOSPC);
}

struct iface *iface_create(const struct gr_iface *conf, const void *api_info) {
	const struct iface_type *type = iface_type_get(conf->type);
	struct iface *iface = NULL;
	bool vrf_ref = false;
	uint16_t ifid;

	if (type == NULL)
		goto fail;
	if (charset_check(conf->name, GR_IFACE_NAME_SIZE) < 0)
		goto fail;
	while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
		if (strcmp(conf->name, iface->name) == 0) {
			iface = NULL;
			errno = EEXIST;
			goto fail;
		}
	}

	iface = rte_zmalloc(__func__, sizeof(*iface) + type->priv_size, RTE_CACHE_LINE_SIZE);
	if (iface == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	if (conf->type != GR_IFACE_TYPE_LOOPBACK) {
		vrf_incref(conf->vrf_id);
		vrf_ref = true;
	}
	if (conf->type == GR_IFACE_TYPE_LOOPBACK && conf->vrf_id) {
		ifid = conf->vrf_id;
		if (reserve_ifid(ifid) < 0)
			goto fail;
	} else if (next_ifid(&ifid) < 0)
		goto fail;

	iface->base = conf->base;
	iface->id = ifid;
	// this is only accessed by the API, no need to copy the name to DPDK memory (hugepages)
	iface->name = strndup(conf->name, GR_IFACE_NAME_SIZE);
	if (iface->name == NULL)
		goto fail;

	if (type->init(iface, api_info) < 0)
		goto fail;

	if (type->set_mtu != NULL && type->set_mtu(iface, iface->mtu) < 0)
		goto fail;
	if (type->set_promisc != NULL
	    && type->set_promisc(iface, iface->flags & GR_IFACE_F_PROMISC) < 0)
		goto fail;
	if (type->set_allmulti != NULL
	    && type->set_allmulti(iface, iface->flags & GR_IFACE_F_ALLMULTI) < 0)
		goto fail;
	if (type->set_up_down != NULL && type->set_up_down(iface, iface->flags & GR_IFACE_F_UP) < 0)
		goto fail;

	ifaces[ifid] = iface;

	memset(iface_stats[ifid], 0, sizeof(iface_stats[ifid]));

	gr_event_push(GR_EVENT_IFACE_POST_ADD, iface);

	return iface;
fail:
	if (iface != NULL) {
		if (vrf_ref)
			vrf_decref(iface->vrf_id);

		free(iface->name);
	}
	rte_free(iface);
	return NULL;
}

int iface_reconfig(
	uint16_t ifid,
	uint64_t set_attrs,
	const struct gr_iface *conf,
	const void *api_info
) {
	const struct iface_type *type;
	struct iface *iface;
	uint16_t old_vrf_id;
	int ret;

	if (set_attrs == 0)
		return errno_set(EINVAL);

	if ((iface = iface_from_id(ifid)) == NULL)
		return -errno;
	if (set_attrs & GR_IFACE_SET_NAME) {
		if (charset_check(conf->name, GR_IFACE_NAME_SIZE) < 0)
			return -errno;

		const struct iface *i = NULL;
		while ((i = iface_next(GR_IFACE_TYPE_UNDEF, i)) != NULL)
			if (i != iface && strcmp(conf->name, i->name) == 0)
				return errno_set(EEXIST);

		char *new_name = strndup(conf->name, GR_IFACE_NAME_SIZE);
		if (new_name == NULL)
			return errno_set(ENOMEM);
		free(iface->name);
		iface->name = new_name;
	}

	type = iface_type_get(iface->type);
	assert(type != NULL);

	if (set_attrs & GR_IFACE_SET_VRF) {
		if (conf->vrf_id >= GR_MAX_VRFS)
			return errno_set(EOVERFLOW);
		old_vrf_id = iface->vrf_id;
		vrf_incref(conf->vrf_id);
	}

	ret = type->reconfig(iface, set_attrs, conf, api_info);
	if (ret < 0) {
		if (set_attrs & GR_IFACE_SET_VRF)
			vrf_decref(conf->vrf_id);
		return ret;
	}

	if (set_attrs & GR_IFACE_SET_VRF) {
		iface->vrf_id = conf->vrf_id;
		vrf_decref(old_vrf_id);
	}

	if (set_attrs & GR_IFACE_SET_MODE) {
		iface->mode = conf->mode;
	}

	if (set_attrs & GR_IFACE_SET_MTU) {
		if ((ret = iface_set_mtu(iface->id, conf->mtu)) < 0)
			return ret;
	}

	if (set_attrs & GR_IFACE_SET_FLAGS) {
		if ((ret = iface_set_promisc(iface->id, conf->flags & GR_IFACE_F_PROMISC)) < 0)
			return ret;
		if ((ret = iface_set_allmulti(iface->id, conf->flags & GR_IFACE_F_ALLMULTI)) < 0)
			return ret;
		if ((ret = iface_set_up_down(iface->id, conf->flags & GR_IFACE_F_UP)) < 0)
			return ret;
	}

	gr_event_push(GR_EVENT_IFACE_POST_RECONFIG, iface);

	return ret;
}

uint16_t ifaces_count(gr_iface_type_t type_id) {
	uint16_t count = 0;

	for (uint16_t ifid = IFACE_ID_FIRST; ifid < MAX_IFACES; ifid++) {
		struct iface *iface = ifaces[ifid];
		if (iface != NULL && (type_id == GR_IFACE_TYPE_UNDEF || iface->type == type_id))
			count++;
	}

	return count;
}

struct iface *iface_next(gr_iface_type_t type_id, const struct iface *prev) {
	uint16_t start_id;

	if (prev == NULL)
		start_id = IFACE_ID_FIRST;
	else
		start_id = prev->id + 1;

	for (uint16_t ifid = start_id; ifid < MAX_IFACES; ifid++) {
		struct iface *iface = ifaces[ifid];
		if (iface != NULL && (type_id == GR_IFACE_TYPE_UNDEF || iface->type == type_id))
			return iface;
	}

	return NULL;
}

struct iface *iface_from_id(uint16_t ifid) {
	struct iface *iface = NULL;
	if (ifid != GR_IFACE_ID_UNDEF && ifid < MAX_IFACES)
		iface = ifaces[ifid];
	if (iface == NULL)
		errno = ENODEV;
	return iface;
}

int iface_get_eth_addr(uint16_t ifid, struct rte_ether_addr *mac) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;

	if (iface == NULL)
		return -errno;

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->get_eth_addr == NULL)
		return errno_set(EOPNOTSUPP);

	return type->get_eth_addr(iface, mac);
}

void iface_add_subinterface(struct iface *parent, struct iface *sub) {
	gr_vec_foreach (struct iface *s, parent->subinterfaces) {
		if (s == sub)
			return;
	}
	gr_vec_add(parent->subinterfaces, sub);
}

void iface_del_subinterface(struct iface *parent, struct iface *sub) {
	for (size_t i = 0; i < gr_vec_len(parent->subinterfaces); i++) {
		if (parent->subinterfaces[i] == sub) {
			gr_vec_del_swap(parent->subinterfaces, i);
			return;
		}
	}
}

int iface_set_eth_addr(uint16_t ifid, const struct rte_ether_addr *mac) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;

	if (iface == NULL)
		return -errno;

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->set_eth_addr == NULL)
		return errno_set(EOPNOTSUPP);

	return type->set_eth_addr(iface, mac);
}

int iface_add_eth_addr(uint16_t ifid, const struct rte_ether_addr *mac) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;

	if (iface == NULL)
		return -errno;

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->add_eth_addr == NULL)
		return errno_set(EOPNOTSUPP);

	return type->add_eth_addr(iface, mac);
}

int iface_del_eth_addr(uint16_t ifid, const struct rte_ether_addr *mac) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;

	if (iface == NULL)
		return -errno;

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->del_eth_addr == NULL)
		return errno_set(EOPNOTSUPP);

	return type->del_eth_addr(iface, mac);
}

int iface_set_mtu(uint16_t ifid, uint16_t mtu) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;

	if (iface == NULL)
		return -errno;

	if (mtu > gr_config.max_mtu)
		return errno_set(ERANGE);

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->set_mtu != NULL)
		return type->set_mtu(iface, mtu);

	iface->mtu = mtu;
	return 0;
}

int iface_set_up_down(uint16_t ifid, bool up) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;

	if (iface == NULL)
		return -errno;

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->set_up_down != NULL)
		return type->set_up_down(iface, up);

	if (!(iface->flags & GR_IFACE_F_UP) && up)
		iface->flags |= GR_IFACE_F_UP;
	else if ((iface->flags & GR_IFACE_F_UP) && !up)
		iface->flags &= ~GR_IFACE_F_UP;

	return 0;
}

int iface_set_promisc(uint16_t ifid, bool enabled) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;

	if (iface == NULL)
		return -errno;

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->set_promisc != NULL)
		return type->set_promisc(iface, enabled);

	if (enabled)
		return errno_set(EOPNOTSUPP);

	return 0;
}

int iface_set_allmulti(uint16_t ifid, bool enabled) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;

	if (iface == NULL)
		return -errno;

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->set_allmulti != NULL)
		return type->set_allmulti(iface, enabled);

	if (enabled)
		return errno_set(EOPNOTSUPP);

	return 0;
}

int iface_add_vlan(uint16_t ifid, uint16_t vlan_id) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;

	if (iface == NULL)
		return -errno;

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->add_vlan == NULL)
		return errno_set(EOPNOTSUPP);

	return type->add_vlan(iface, vlan_id);
}

int iface_del_vlan(uint16_t ifid, uint16_t vlan_id) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;

	if (iface == NULL)
		return -errno;

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->del_vlan == NULL)
		return errno_set(EOPNOTSUPP);

	return type->del_vlan(iface, vlan_id);
}

int iface_destroy(uint16_t ifid) {
	struct iface *iface = iface_from_id(ifid);
	const struct iface_type *type;
	int ret;

	if (iface == NULL)
		return -errno;

	if (gr_vec_len(iface->subinterfaces) != 0)
		return errno_set(EBUSY);

	// interface is still up, send status down
	if (iface->flags & GR_IFACE_F_UP) {
		iface->flags &= ~GR_IFACE_F_UP;
		gr_event_push(GR_EVENT_IFACE_STATUS_DOWN, iface);
	}
	gr_event_push(GR_EVENT_IFACE_PRE_REMOVE, iface);
	if (iface->type != GR_IFACE_TYPE_LOOPBACK)
		vrf_decref(iface->vrf_id);
	nexthop_iface_cleanup(ifid);

	ifaces[ifid] = NULL;

	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);

	type = iface_type_get(iface->type);
	assert(type != NULL);
	ret = type->fini(iface);
	free(iface->name);
	gr_vec_free(iface->subinterfaces);
	rte_free(iface);

	return ret;
}

static void iface_init(struct event_base *) {
	ifaces = rte_calloc(__func__, MAX_IFACES, sizeof(struct iface *), RTE_CACHE_LINE_SIZE);
	if (ifaces == NULL)
		ABORT("rte_calloc(ifaces)");
}

static void iface_fini(struct event_base *) {
	struct iface *iface;
	uint16_t ifid;

	// Destroy all virtual interface first before removing DPDK ports.
	for (ifid = IFACE_ID_FIRST; ifid < MAX_IFACES; ifid++) {
		iface = ifaces[ifid];
		if (iface != NULL && iface->type != GR_IFACE_TYPE_PORT
		    && iface->type != GR_IFACE_TYPE_LOOPBACK) {
			if (iface_destroy(ifid) < 0)
				LOG(ERR, "iface_destroy: %s", strerror(errno));
			ifaces[ifid] = NULL;
		}
	}

	// Finally, destroy DPDK ports.
	for (ifid = IFACE_ID_FIRST; ifid < MAX_IFACES; ifid++) {
		iface = ifaces[ifid];
		if (iface == NULL || iface->type == GR_IFACE_TYPE_LOOPBACK)
			continue;
		if (iface_destroy(ifid) < 0)
			LOG(ERR, "iface_destroy: %s", strerror(errno));
	}

	rte_free(ifaces);
	ifaces = NULL;
}

static struct gr_module iface_module = {
	.name = "iface",
	.depends_on = "*route",
	.init = iface_init,
	.fini = iface_fini,
};

static void iface_event(uint32_t event, const void *obj) {
	const struct iface *iface = obj;
	char *str = "";
	switch (event) {
	case GR_EVENT_IFACE_POST_ADD:
		str = "POST_ADD";
		break;
	case GR_EVENT_IFACE_PRE_REMOVE:
		str = "PRE_REMOVE";
		break;
	case GR_EVENT_IFACE_POST_RECONFIG:
		str = "POST_RECONFIG";
		break;
	case GR_EVENT_IFACE_STATUS_UP:
		str = "STATUS_UP";
		gr_vec_foreach (struct iface *s, iface->subinterfaces) {
			s->state |= GR_IFACE_S_RUNNING;
			gr_event_push(event, s);
		}
		break;
	case GR_EVENT_IFACE_STATUS_DOWN:
		str = "STATUS_DOWN";
		gr_vec_foreach (struct iface *s, iface->subinterfaces) {
			s->state &= ~GR_IFACE_S_RUNNING;
			gr_event_push(event, s);
		}
		break;
	default:
		str = "?";
		break;
	}
	LOG(DEBUG, "iface event [0x%08x] %s triggered for iface %s.", event, str, iface->name);
}

static struct gr_event_subscription iface_event_handler = {
	.callback = iface_event,
	.ev_count = 5,
	.ev_types = {
		GR_EVENT_IFACE_POST_ADD,
		GR_EVENT_IFACE_PRE_REMOVE,
		GR_EVENT_IFACE_POST_RECONFIG,
		GR_EVENT_IFACE_STATUS_UP,
		GR_EVENT_IFACE_STATUS_DOWN,
	},
};

RTE_INIT(iface_constructor) {
	gr_register_module(&iface_module);
	gr_event_subscribe(&iface_event_handler);
}
