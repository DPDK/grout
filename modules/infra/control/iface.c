// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "gr_iface.h"

#include <gr_control.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_string.h>

#include <event2/event.h>
#include <rte_malloc.h>

#include <errno.h>
#include <string.h>
#include <sys/queue.h>
#include <wchar.h>

static STAILQ_HEAD(, iface_type) types = STAILQ_HEAD_INITIALIZER(types);

struct iface_type *iface_type_get(uint16_t type_id) {
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
	STAILQ_INSERT_TAIL(&types, type, next);
}

static struct iface **ifaces;

static int next_ifid(uint16_t *ifid) {
	for (uint16_t i = 0; i < MAX_IFACES; i++) {
		if (ifaces[i] == NULL) {
			*ifid = i;
			return 0;
		}
	}
	errno = ENOSPC;
	return -1;
}

static STAILQ_HEAD(, iface_event_handler) event_handlers = STAILQ_HEAD_INITIALIZER(event_handlers);

void iface_event_register_handler(struct iface_event_handler *cb) {
	STAILQ_INSERT_TAIL(&event_handlers, cb, next);
}

void iface_event_notify(iface_event_t event, struct iface *iface) {
	struct iface_event_handler *iface_event_handler;
	STAILQ_FOREACH (iface_event_handler, &event_handlers, next)
		iface_event_handler->callback(event, iface);
}

struct iface *iface_create(
	uint16_t type_id,
	uint16_t flags,
	uint16_t mtu,
	uint16_t vrf_id,
	const char *name,
	const void *api_info
) {
	struct iface_type *type = iface_type_get(type_id);
	struct iface *iface = NULL;
	uint16_t ifid;

	if (type == NULL)
		goto fail;
	if (utf8_check(name, GR_IFACE_NAME_SIZE) < 0)
		goto fail;

	iface = rte_zmalloc(__func__, sizeof(*iface) + type->info_size, RTE_CACHE_LINE_SIZE);
	if (iface == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	if (next_ifid(&ifid) < 0)
		goto fail;

	iface->id = ifid;
	iface->type_id = type_id;
	iface->flags = flags;
	iface->mtu = mtu;
	iface->vrf_id = vrf_id;
	// this is only accessed by the API, no need to copy the name to DPDK memory (hugepages)
	iface->name = strndup(name, GR_IFACE_NAME_SIZE);
	if (iface->name == NULL)
		goto fail;

	if (type->init(iface, api_info) < 0)
		goto fail;

	ifaces[ifid] = iface;

	iface_event_notify(IFACE_EVENT_POST_ADD, iface);

	return iface;
fail:
	if (iface != NULL)
		free(iface->name);
	rte_free(iface);
	return NULL;
}

int iface_reconfig(
	uint16_t ifid,
	uint64_t set_attrs,
	uint16_t flags,
	uint16_t mtu,
	uint16_t vrf_id,
	const char *name,
	const void *api_info
) {
	struct iface_type *type;
	struct iface *iface;

	if (set_attrs == 0)
		return errno_set(EINVAL);
	if ((iface = iface_from_id(ifid)) == NULL)
		return -1;
	if (set_attrs & GR_IFACE_SET_NAME) {
		if (utf8_check(name, GR_IFACE_NAME_SIZE) < 0)
			return -1;

		const struct iface *i = NULL;
		while ((i = iface_next(GR_IFACE_TYPE_UNDEF, i)) != NULL)
			if (i != iface && strcmp(name, i->name) == 0)
				return errno_set(EEXIST);

		char *new_name = strndup(name, GR_IFACE_NAME_SIZE);
		if (new_name == NULL)
			return -1;
		free(iface->name);
		iface->name = new_name;
	}

	type = iface_type_get(iface->type_id);
	return type->reconfig(iface, set_attrs, flags, mtu, vrf_id, api_info);
}

uint16_t ifaces_count(uint16_t type_id) {
	uint16_t count = 0;

	for (uint16_t ifid = 0; ifid < MAX_IFACES; ifid++) {
		struct iface *iface = ifaces[ifid];
		if (iface != NULL && (type_id == GR_IFACE_TYPE_UNDEF || iface->type_id == type_id))
			count++;
	}

	return count;
}

struct iface *iface_next(uint16_t type_id, const struct iface *prev) {
	uint16_t start_id;

	if (prev == NULL)
		start_id = 0;
	else
		start_id = prev->id + 1;

	for (uint16_t ifid = start_id; ifid < MAX_IFACES; ifid++) {
		struct iface *iface = ifaces[ifid];
		if (iface != NULL && (type_id == GR_IFACE_TYPE_UNDEF || iface->type_id == type_id))
			return iface;
	}

	return NULL;
}

struct iface *iface_from_id(uint16_t ifid) {
	struct iface *iface = NULL;
	if (ifid < MAX_IFACES)
		iface = ifaces[ifid];
	if (iface == NULL)
		errno = ENODEV;
	return iface;
}

int iface_get_eth_addr(uint16_t ifid, struct rte_ether_addr *mac) {
	struct iface *iface = iface_from_id(ifid);
	struct iface_type *type;

	if (iface == NULL)
		return -1;

	type = iface_type_get(iface->type_id);
	if (type->get_eth_addr == NULL)
		return errno_set(EOPNOTSUPP);

	return type->get_eth_addr(iface, mac);
}

int iface_destroy(uint16_t ifid) {
	struct iface *iface = iface_from_id(ifid);
	struct iface_type *type;
	int ret;

	if (iface == NULL)
		return -1;

	iface_event_notify(IFACE_EVENT_PRE_REMOVE, iface);

	ifaces[ifid] = NULL;
	type = iface_type_get(iface->type_id);
	ret = type->fini(iface);
	free(iface->name);
	rte_free(iface);

	return ret;
}

static void iface_init(struct event_base *) {
	ifaces = rte_calloc(__func__, MAX_IFACES, sizeof(struct iface *), RTE_CACHE_LINE_SIZE);
	if (ifaces == NULL)
		ABORT("rte_zmalloc(ifaces)");
}

static void iface_fini(struct event_base *) {
	struct iface *iface;
	uint16_t ifid;

	// Destroy all virtual interface first before removing DPDK ports.
	for (ifid = 0; ifid < MAX_IFACES; ifid++) {
		iface = ifaces[ifid];
		if (iface != NULL && iface->type_id != GR_IFACE_TYPE_PORT) {
			if (iface_destroy(ifid) < 0)
				LOG(ERR, "iface_destroy: %s", strerror(errno));
			ifaces[ifid] = NULL;
		}
	}
	// Finally, destroy DPDK ports.
	for (ifid = 0; ifid < MAX_IFACES; ifid++) {
		iface = ifaces[ifid];
		if (iface == NULL)
			continue;
		if (iface_destroy(ifid) < 0)
			LOG(ERR, "iface_destroy: %s", strerror(errno));
	}

	rte_free(ifaces);
	ifaces = NULL;
}

static struct gr_module iface_module = {
	.name = "iface",
	.init = iface_init,
	.fini = iface_fini,
	.fini_prio = 1000,
};

static void iface_event_debug(iface_event_t event, struct iface *iface) {
	const char *str = "IFACE_EVENT_UNKNOWN";
#define IFACE_EVENT(name) #name
	const char *evt_to_str[] = {IFACE_EVENTS};
#undef IFACE_EVENT

	if (event < (sizeof(evt_to_str) / sizeof(evt_to_str[0])))
		str = evt_to_str[event];

	LOG(DEBUG, "iface event [%d] %s triggered for iface %s.", event, str, iface->name);
}

static struct iface_event_handler iface_event_debug_handler = {
	.callback = iface_event_debug,
};

RTE_INIT(iface_constructor) {
	gr_register_module(&iface_module);
	iface_event_register_handler(&iface_event_debug_handler);
}
