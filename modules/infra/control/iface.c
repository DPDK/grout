// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_iface.h"

#include <br_control.h>
#include <br_log.h>
#include <br_macro.h>
#include <br_string.h>

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

struct iface *iface_create(
	uint16_t type_id,
	uint32_t flags,
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
	if (utf8_check(name, MEMBER_SIZE(struct iface, name)) < 0)
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
	memccpy(iface->name, name, 0, sizeof(iface->name));

	if (type->init(iface, api_info) < 0)
		goto fail;

	ifaces[ifid] = iface;

	return iface;
fail:
	rte_free(iface);
	return NULL;
}

int iface_reconfig(
	uint16_t ifid,
	uint64_t set_attrs,
	uint32_t flags,
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

	if (set_attrs & BR_IFACE_SET_NAME) {
		if (utf8_check(name, MEMBER_SIZE(struct iface, name)) < 0)
			return -1;
		memccpy(iface->name, name, 0, sizeof(iface->name));
	}
	if (set_attrs & BR_IFACE_SET_FLAGS)
		iface->flags = flags;
	if (set_attrs & BR_IFACE_SET_MTU)
		iface->mtu = mtu;
	if (set_attrs & BR_IFACE_SET_VRF)
		iface->vrf_id = vrf_id;

	type = iface_type_get(iface->type_id);
	return type->reconfig(iface, set_attrs, api_info);
}

uint16_t ifaces_count(uint16_t type_id) {
	uint16_t count = 0;

	for (uint16_t ifid = 0; ifid < MAX_IFACES; ifid++) {
		struct iface *iface = ifaces[ifid];
		if (iface != NULL && (type_id == BR_IFACE_TYPE_UNDEF || iface->type_id == type_id))
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
		if (iface != NULL && (type_id == BR_IFACE_TYPE_UNDEF || iface->type_id == type_id))
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

	ifaces[ifid] = NULL;
	type = iface_type_get(iface->type_id);
	ret = type->fini(iface);
	rte_free(iface);

	return ret;
}

static void iface_init(void) {
	ifaces = rte_calloc(__func__, MAX_IFACES, sizeof(struct iface *), RTE_CACHE_LINE_SIZE);
	if (ifaces == NULL)
		ABORT("rte_zmalloc(ifaces)");
}

static void iface_fini(void) {
	for (uint16_t ifid = 0; ifid < MAX_IFACES; ifid++) {
		struct iface *iface = ifaces[ifid];
		if (iface == NULL)
			continue;
		if (iface_destroy(ifid) < 0)
			LOG(ERR, "iface_destroy: %s", strerror(errno));
	}
	rte_free(ifaces);
	ifaces = NULL;
}

static struct br_module iface_module = {
	.name = "iface",
	.init = iface_init,
	.fini = iface_fini,
	.fini_prio = 1000,
};

RTE_INIT(iface_constructor) {
	br_register_module(&iface_module);
}
