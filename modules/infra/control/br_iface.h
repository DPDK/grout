// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_IFACE
#define _BR_INFRA_IFACE

#include <br_bitops.h>
#include <br_infra.h>

#include <rte_ether.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

struct iface {
	uint16_t id;
	uint16_t type_id;
	uint16_t flags;
	uint16_t state;
	uint16_t mtu;
	uint16_t vrf_id; // L3 addressing and routing domain
	char name[64];
	uint8_t info[/* size depends on type */];
};

#define IFACE_SET_ALL UINT64_C(0xffffffffffffffff)

typedef int (*iface_init_t)(struct iface *, const void *api_info);
typedef int (*iface_reconfig_t)(struct iface *, uint64_t set_attrs, const void *api_info);
typedef int (*iface_fini_t)(struct iface *);
typedef int (*iface_get_eth_addr_t)(const struct iface *, struct rte_ether_addr *);
typedef void (*iface_to_api_t)(void *api_info, const struct iface *);

struct iface_type {
	uint16_t id;
	size_t info_size;
	iface_init_t init;
	iface_reconfig_t reconfig;
	iface_fini_t fini;
	iface_get_eth_addr_t get_eth_addr;
	iface_to_api_t to_api;
	const char *name;
	STAILQ_ENTRY(iface_type) next;
};

void iface_type_register(struct iface_type *);
struct iface_type *iface_type_get(uint16_t type_id);
struct iface *iface_create(
	uint16_t type_id,
	uint32_t flags,
	uint16_t mtu,
	uint16_t vrf_id,
	const char *name,
	const void *api_info
);
int iface_reconfig(
	uint16_t ifid,
	uint64_t set_attrs,
	uint32_t flags,
	uint16_t mtu,
	uint16_t vrf_id,
	const char *name,
	const void *api_info
);
int iface_destroy(uint16_t ifid);
struct iface *iface_from_id(uint16_t ifid);
int iface_get_eth_addr(uint16_t ifid, struct rte_ether_addr *);
uint16_t ifaces_count(uint16_t type_id);
struct iface *iface_next(uint16_t type_id, const struct iface *prev);

#define MAX_IFACES 1024

#endif
