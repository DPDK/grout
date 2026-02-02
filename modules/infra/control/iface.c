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
#include <gr_vrf.h>

#include <event2/event.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <errno.h>
#include <string.h>
#include <sys/queue.h>
#include <wchar.h>

static const struct iface_type *iface_types[UINT_NUM_VALUES(gr_iface_type_t)];

struct iface_stats iface_stats[GR_MAX_IFACES][RTE_MAX_LCORE];

static bool iface_type_valid(gr_iface_type_t type) {
	switch (type) {
	case GR_IFACE_TYPE_VRF:
	case GR_IFACE_TYPE_PORT:
	case GR_IFACE_TYPE_VLAN:
	case GR_IFACE_TYPE_IPIP:
	case GR_IFACE_TYPE_BOND:
		return true;
	case GR_IFACE_TYPE_UNDEF:
	case GR_IFACE_TYPE_COUNT:
		break;
	}
	return false;
}

const struct iface_type *iface_type_get(gr_iface_type_t type_id) {
	return iface_types[type_id];
}

void iface_type_register(const struct iface_type *type) {
	if (!iface_type_valid(type->id))
		ABORT("invalid iface type id: %u", type->id);
	if (iface_type_get(type->id) != NULL)
		ABORT("duplicate iface type id: %u", type->id);
	iface_types[type->id] = type;
}

struct reserved_name {
	const char *name;
	bool prefix;
};

static gr_vec struct reserved_name *reserved_names;

void iface_name_reserve(const char *name, bool prefix) {
	struct reserved_name r = {.name = name, .prefix = prefix};
	gr_vec_add(reserved_names, r);
}

static bool iface_name_is_reserved(const char *name) {
	gr_vec_foreach (struct reserved_name r, reserved_names) {
		if (r.prefix) {
			if (strncmp(name, r.name, strlen(r.name)) == 0)
				return true;
		} else {
			if (strncmp(name, r.name, GR_IFACE_NAME_SIZE) == 0)
				return true;
		}
	}
	return false;
}

static int iface_name_is_valid(const struct gr_iface *conf, const struct iface *exclude) {
	const struct iface *iface = NULL;

	if (charset_check(conf->name, GR_IFACE_NAME_SIZE) < 0)
		return -errno;
	while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
		if (iface != exclude && strcmp(conf->name, iface->name) == 0)
			return errno_set(EEXIST);
	}
	if (iface_name_is_reserved(conf->name)) {
		// only default vrf can be named "GR_DEFAULT_VRF_NAME"
		if (conf->id != GR_VRF_DEFAULT_ID
		    || strncmp(conf->name, GR_DEFAULT_VRF_NAME, GR_IFACE_NAME_SIZE) != 0)
			return errno_set(EINVAL);
	}

	return 0;
}

#define IFACE_ID_FIRST GR_IFACE_ID_UNDEF + 1

// the first slot is wasted by GR_IFACE_ID_UNDEF
static struct iface **ifaces;

// Reserve a specific interface id.
// Returns 0 on success, -errno on failure.
static int reserve_ifid(uint16_t ifid) {
	if (ifid >= GR_MAX_IFACES)
		return errno_set(EINVAL);

	if (ifaces[ifid] == NULL)
		return 0;

	return errno_set(EBUSY);
}

// Slot GR_VRF_DEFAULT_ID (1) is reserved for the default VRF.
static int next_ifid(uint16_t *ifid) {
	for (uint16_t i = GR_VRF_DEFAULT_ID + 1; i < GR_MAX_IFACES; i++) {
		if (reserve_ifid(i) < 0)
			continue;

		*ifid = i;
		return 0;
	}

	return errno_set(ENOSPC);
}

// Get or create the default VRF. Returns GR_VRF_DEFAULT_ID, or 0 on error.
static uint16_t get_or_create_default_vrf(void) {
	if (iface_from_id(GR_VRF_DEFAULT_ID) != NULL)
		return GR_VRF_DEFAULT_ID;

	// Create the default VRF with the reserved ID.
	struct gr_iface vrf_conf = {
		.id = GR_VRF_DEFAULT_ID,
		.type = GR_IFACE_TYPE_VRF,
		.flags = GR_IFACE_F_UP,
		.name = GR_DEFAULT_VRF_NAME,
	};

	struct iface *vrf = iface_create(&vrf_conf, NULL);
	if (vrf == NULL)
		return 0;

	assert(vrf->id == GR_VRF_DEFAULT_ID);
	return vrf->id;
}

struct iface *iface_create(const struct gr_iface *conf, const void *api_info) {
	const struct iface_type *type = iface_type_get(conf->type);
	struct iface *iface = NULL;
	bool type_init = false;
	bool vrf_ref = false;
	uint16_t ifid;

	if (type == NULL) {
		errno = ENODEV;
		goto fail;
	}
	if (iface_name_is_valid(conf, NULL) < 0)
		goto fail;
	iface = rte_zmalloc(__func__, sizeof(*iface) + type->priv_size, RTE_CACHE_LINE_SIZE);
	if (iface == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	iface->base = conf->base;

	if (conf->domain_id == GR_IFACE_ID_UNDEF) {
		if (conf->type != GR_IFACE_TYPE_VRF) {
			uint16_t vrf_id = conf->vrf_id;

			// Auto-create default VRF if no VRF specified
			if (vrf_id == GR_IFACE_ID_UNDEF) {
				vrf_id = get_or_create_default_vrf();
				if (vrf_id == GR_IFACE_ID_UNDEF)
					goto fail;
			}
			if (vrf_incref(vrf_id) < 0)
				goto fail;
			vrf_ref = true;
			iface->vrf_id = vrf_id;
		}

		iface->mode = GR_IFACE_MODE_VRF;
	}
	if (conf->id != GR_IFACE_ID_UNDEF) {
		if (reserve_ifid(conf->id) < 0)
			goto fail;
		ifid = conf->id;
	} else {
		if (next_ifid(&ifid) < 0)
			goto fail;
	}

	iface->id = ifid;
	iface->speed = RTE_ETH_SPEED_NUM_UNKNOWN;
	// this is only accessed by the API, no need to copy the name to DPDK memory (hugepages)
	iface->name = strndup(conf->name, GR_IFACE_NAME_SIZE);
	if (iface->name == NULL)
		goto fail;

	if (type->init(iface, api_info) < 0)
		goto fail;
	type_init = true;

	if (conf->domain_id != GR_IFACE_ID_UNDEF) {
		const struct iface_type *t;
		struct iface *domain;

		domain = iface_from_id(conf->domain_id);
		if (domain == NULL)
			goto fail;

		t = iface_type_get(domain->type);
		assert(t != NULL);

		if (t->attach_domain == NULL) {
			errno = EMEDIUMTYPE;
			goto fail;
		}
		if (t->attach_domain(domain, iface) < 0)
			goto fail;

		assert(iface->domain_id != GR_IFACE_ID_UNDEF);
		assert(iface->mode != GR_IFACE_MODE_VRF);
	}

	ifaces[ifid] = iface;

	memset(iface_stats[ifid], 0, sizeof(iface_stats[ifid]));

	gr_event_push(GR_EVENT_IFACE_ADD, iface);
	gr_event_push(GR_EVENT_IFACE_POST_ADD, iface);

	if (iface_set_mtu(iface, iface->mtu) < 0)
		goto destroy;

	if (iface_set_promisc(iface, iface->flags & GR_IFACE_F_PROMISC) < 0)
		goto destroy;

	if (iface_set_up_down(iface, iface->flags & GR_IFACE_F_UP) < 0)
		goto destroy;

	return iface;
fail:
	if (vrf_ref)
		vrf_decref(iface->vrf_id);
	if (type_init)
		type->fini(iface);
	if (iface != NULL)
		free(iface->name);
	rte_free(iface);
	return NULL;
destroy:
	iface_destroy(iface);
	return NULL;
}

static void detach_domain(struct iface *iface) {
	const struct iface_type *type;
	struct iface *domain;

	if (iface->mode == GR_IFACE_MODE_VRF) {
		if (iface->type != GR_IFACE_TYPE_VRF)
			vrf_decref(iface->vrf_id);
		return;
	}

	domain = iface_from_id(iface->domain_id);
	if (domain == NULL)
		return;

	type = iface_type_get(domain->type);
	assert(type != NULL);

	if (type->detach_domain == NULL)
		iface->domain_id = GR_IFACE_ID_UNDEF;
	else if (type->detach_domain(domain, iface) < 0)
		LOG(WARNING, "%s: detach from %s: %s", iface->name, domain->name, strerror(errno));
}

int iface_reconfig(
	uint16_t ifid,
	uint64_t set_attrs,
	const struct gr_iface *conf,
	const void *api_info
) {
	const struct iface_type *type;
	struct iface *iface;
	int ret;

	if (set_attrs == 0)
		return errno_set(EINVAL);

	if ((iface = iface_from_id(ifid)) == NULL)
		return -errno;

	if (set_attrs & GR_IFACE_SET_NAME) {
		if (iface_name_is_valid(conf, iface) < 0)
			return -errno;

		char *new_name = strndup(conf->name, GR_IFACE_NAME_SIZE);
		if (new_name == NULL)
			return errno_set(ENOMEM);
		free(iface->name);
		iface->name = new_name;
	}

	type = iface_type_get(iface->type);
	assert(type != NULL);

	if (set_attrs & GR_IFACE_SET_VRF) {
		if (vrf_incref(conf->vrf_id) < 0)
			return -errno;
	}
	ret = type->reconfig(iface, set_attrs, conf, api_info);
	if (ret < 0)
		goto err;

	if (set_attrs & GR_IFACE_SET_MTU) {
		if ((ret = iface_set_mtu(iface, conf->mtu)) < 0)
			goto err;
	}

	if (set_attrs & GR_IFACE_SET_FLAGS) {
		if ((ret = iface_set_promisc(iface, conf->flags & GR_IFACE_F_PROMISC)) < 0)
			goto err;
		if ((ret = iface_set_up_down(iface, conf->flags & GR_IFACE_F_UP)) < 0)
			goto err;
	}

	if (set_attrs & GR_IFACE_SET_VRF) {
		detach_domain(iface);
		assert(iface->domain_id == GR_IFACE_ID_UNDEF);
		iface->vrf_id = conf->vrf_id;
		iface->mode = GR_IFACE_MODE_VRF;
	} else if (set_attrs & GR_IFACE_SET_DOMAIN) {
		struct iface *domain = iface_from_id(conf->domain_id);
		if (domain == NULL)
			goto err;

		type = iface_type_get(domain->type);
		assert(type != NULL);

		if (type->attach_domain == NULL) {
			errno = EMEDIUMTYPE;
			goto err;
		}

		detach_domain(iface);

		if ((ret = type->attach_domain(domain, iface)) < 0)
			goto err;

		assert(iface->domain_id != GR_IFACE_ID_UNDEF);
		assert(iface->mode != GR_IFACE_MODE_VRF);
	}

	gr_event_push(GR_EVENT_IFACE_POST_RECONFIG, iface);

	return 0;
err:
	if (set_attrs & GR_IFACE_SET_VRF)
		vrf_decref(conf->vrf_id);

	return ret;
}

uint16_t ifaces_count(gr_iface_type_t type_id) {
	uint16_t count = 0;

	for (uint16_t ifid = IFACE_ID_FIRST; ifid < GR_MAX_IFACES; ifid++) {
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

	for (uint16_t ifid = start_id; ifid < GR_MAX_IFACES; ifid++) {
		struct iface *iface = ifaces[ifid];
		if (iface != NULL && (type_id == GR_IFACE_TYPE_UNDEF || iface->type == type_id))
			return iface;
	}

	return NULL;
}

struct iface *iface_from_id(uint16_t ifid) {
	struct iface *iface = NULL;
	if (ifid != GR_IFACE_ID_UNDEF && ifid < GR_MAX_IFACES)
		iface = ifaces[ifid];
	if (iface == NULL)
		errno = ENODEV;
	return iface;
}

int iface_get_eth_addr(const struct iface *iface, struct rte_ether_addr *mac) {
	const struct iface_type *type;

	if (iface == NULL)
		return errno_set(EINVAL);

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

int iface_set_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	const struct iface_type *type;

	if (iface == NULL)
		return errno_set(EINVAL);

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->set_eth_addr == NULL)
		return errno_set(EOPNOTSUPP);

	return type->set_eth_addr(iface, mac);
}

int iface_add_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	const struct iface_type *type;

	if (iface == NULL)
		return errno_set(EINVAL);

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->add_eth_addr == NULL)
		return errno_set(EOPNOTSUPP);

	return type->add_eth_addr(iface, mac);
}

int iface_del_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	const struct iface_type *type;

	if (iface == NULL)
		return errno_set(EINVAL);

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->del_eth_addr == NULL)
		return errno_set(EOPNOTSUPP);

	return type->del_eth_addr(iface, mac);
}

int iface_set_mtu(struct iface *iface, uint16_t mtu) {
	const struct iface_type *type;

	if (iface == NULL)
		return errno_set(EINVAL);

	if (mtu == 0)
		mtu = 1500;
	if (mtu < 1280 || mtu > gr_config.max_mtu)
		return errno_set(ERANGE);

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->set_mtu != NULL)
		return type->set_mtu(iface, mtu);

	iface->mtu = mtu;
	return 0;
}

int iface_set_up_down(struct iface *iface, bool up) {
	const struct iface_type *type;

	if (iface == NULL)
		return errno_set(EINVAL);

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->set_up_down != NULL)
		return type->set_up_down(iface, up);

	if (!(iface->flags & GR_IFACE_F_UP) && up) {
		iface->flags |= GR_IFACE_F_UP;
		iface->state |= GR_IFACE_S_RUNNING;
		gr_event_push(GR_EVENT_IFACE_STATUS_UP, iface);
	} else if ((iface->flags & GR_IFACE_F_UP) && !up) {
		iface->flags &= ~GR_IFACE_F_UP;
		iface->state &= ~GR_IFACE_S_RUNNING;
		gr_event_push(GR_EVENT_IFACE_STATUS_DOWN, iface);
	}

	return 0;
}

int iface_set_promisc(struct iface *iface, bool enabled) {
	const struct iface_type *type;

	if (iface == NULL)
		return errno_set(EINVAL);

	type = iface_type_get(iface->type);
	assert(type != NULL);
	if (type->set_promisc != NULL)
		return type->set_promisc(iface, enabled);

	if (enabled)
		return errno_set(EOPNOTSUPP);

	return 0;
}

int iface_destroy(struct iface *iface) {
	const struct iface_type *type;
	int ret;

	if (iface == NULL)
		return errno_set(EINVAL);

	if (gr_vec_len(iface->subinterfaces) != 0)
		return errno_set(EBUSY);
	if (iface->type == GR_IFACE_TYPE_VRF && vrf_has_interfaces(iface->id))
		return errno_set(EBUSY);

	gr_event_push(GR_EVENT_IFACE_PRE_REMOVE, iface);
	// interface is still up, send status down
	if (iface->flags & GR_IFACE_F_UP) {
		iface->flags &= ~GR_IFACE_F_UP;
		gr_event_push(GR_EVENT_IFACE_STATUS_DOWN, iface);
	}
	detach_domain(iface);

	ifaces[iface->id] = NULL;

	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);

	// Push IFACE_REMOVE event after RCU sync to ensure all datapath threads
	// have seen that this iface is gone. At this point, only packets already
	// in the control queue may still reference it. The event triggers
	// a drain that frees those packets before type->fini() frees the iface.
	gr_event_push(GR_EVENT_IFACE_REMOVE, iface);

	type = iface_type_get(iface->type);
	assert(type != NULL);
	ret = type->fini(iface);
	free(iface->name);
	gr_vec_free(iface->subinterfaces);
	rte_free(iface);

	return ret;
}

static void iface_init(struct event_base *) {
	ifaces = rte_calloc(__func__, GR_MAX_IFACES, sizeof(struct iface *), RTE_CACHE_LINE_SIZE);
	if (ifaces == NULL)
		ABORT("rte_calloc(ifaces)");
}

static void iface_fini(struct event_base *) {
	struct iface *iface;
	uint16_t ifid;

	// Destroy all virtual interface first before removing DPDK ports.
	for (ifid = IFACE_ID_FIRST; ifid < GR_MAX_IFACES; ifid++) {
		iface = ifaces[ifid];
		if (iface != NULL && iface->type != GR_IFACE_TYPE_PORT
		    && iface->type != GR_IFACE_TYPE_VRF) {
			if (iface_destroy(iface) < 0)
				LOG(ERR, "iface_destroy: %s", strerror(errno));
			ifaces[ifid] = NULL;
		}
	}

	// Then, destroy DPDK ports.
	for (ifid = IFACE_ID_FIRST; ifid < GR_MAX_IFACES; ifid++) {
		iface = ifaces[ifid];
		if (iface == NULL || iface->type == GR_IFACE_TYPE_VRF)
			continue;
		if (iface_destroy(iface) < 0)
			LOG(ERR, "iface_destroy: %s", strerror(errno));
	}

	// Finally, destroy VRF interfaces.
	for (ifid = IFACE_ID_FIRST; ifid < GR_MAX_IFACES; ifid++) {
		iface = ifaces[ifid];
		if (iface == NULL)
			continue;
		assert(iface->type == GR_IFACE_TYPE_VRF);

		if (iface_destroy(iface) < 0)
			LOG(ERR, "iface_destroy: %s", strerror(errno));
	}

	gr_vec_free(reserved_names);
	rte_free(ifaces);
	ifaces = NULL;
}

static struct gr_module iface_module = {
	.name = "iface",
	.depends_on = "*route,control_queue",
	.init = iface_init,
	.fini = iface_fini,
};

static void iface_event(uint32_t event, const void *obj) {
	const struct iface *iface = obj;
	char *str = "";
	switch (event) {
	case GR_EVENT_IFACE_ADD:
		str = "ADD";
		break;
	case GR_EVENT_IFACE_POST_ADD:
		str = "POST_ADD";
		break;
	case GR_EVENT_IFACE_PRE_REMOVE:
		str = "PRE_REMOVE";
		break;
	case GR_EVENT_IFACE_REMOVE:
		str = "REMOVE";
		break;
	case GR_EVENT_IFACE_POST_RECONFIG:
		str = "POST_RECONFIG";
		break;
	case GR_EVENT_IFACE_STATUS_UP:
		str = "STATUS_UP";
		gr_vec_foreach (struct iface *s, iface->subinterfaces) {
			s->state |= GR_IFACE_S_RUNNING;
			s->speed = iface->speed;
			gr_event_push(event, s);
		}
		break;
	case GR_EVENT_IFACE_STATUS_DOWN:
		str = "STATUS_DOWN";
		gr_vec_foreach (struct iface *s, iface->subinterfaces) {
			s->state &= ~GR_IFACE_S_RUNNING;
			s->speed = RTE_ETH_SPEED_NUM_UNKNOWN;
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
	.ev_count = 7,
	.ev_types = {
		GR_EVENT_IFACE_ADD,
		GR_EVENT_IFACE_POST_ADD,
		GR_EVENT_IFACE_PRE_REMOVE,
		GR_EVENT_IFACE_REMOVE,
		GR_EVENT_IFACE_POST_RECONFIG,
		GR_EVENT_IFACE_STATUS_UP,
		GR_EVENT_IFACE_STATUS_DOWN,
	},
};

RTE_INIT(iface_constructor) {
	gr_register_module(&iface_module);
	gr_event_subscribe(&iface_event_handler);
}
