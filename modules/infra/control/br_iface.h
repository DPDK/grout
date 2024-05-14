// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_IFACE
#define _BR_INFRA_IFACE

#include <br_bitops.h>

#include <rte_ether.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

// Value for iface.type
#define IFACE_TYPE_UNDEF 0x0000

// Interface configure flags
#define IFACE_F_UP BR_BIT16(0)
#define IFACE_F_PROMISC BR_BIT16(1)
#define IFACE_F_ALLMULTI BR_BIT16(2)
// Interface state flags
#define IFACE_S_RUNNING BR_BIT16(0)

// Interface reconfig attributes
#define IFACE_SET_FLAGS BR_BIT64(0)
#define IFACE_SET_MTU BR_BIT64(1)
#define IFACE_SET_NAME BR_BIT64(2)
#define IFACE_SET_GENERIC UINT64_C(0x00000000ffffffff)
#define IFACE_SET_SPECIFIC UINT64_C(0xffffffff00000000)
#define IFACE_SET_ALL UINT64_C(0xffffffffffffffff)

struct iface {
	uint16_t id;
	uint16_t type_id;
	uint16_t flags;
	uint16_t state;
	uint16_t mtu;
	char name[64];
	uint8_t info[/* size depends on type */];
};

typedef int (*iface_init_t)(struct iface *);
typedef int (*iface_reconfig_t)(struct iface *, uint64_t set_attrs, void *new_info);
typedef int (*iface_fini_t)(struct iface *);
typedef int (*iface_get_eth_addr_t)(const struct iface *, struct rte_ether_addr *);

struct iface_type {
	uint16_t id;
	size_t info_size;
	iface_init_t init;
	iface_reconfig_t reconfig;
	iface_fini_t fini;
	iface_get_eth_addr_t get_eth_addr;
	const char *name;
	STAILQ_ENTRY(iface_type) next;
};

void iface_type_register(struct iface_type *);
struct iface_type *iface_type_get(uint16_t type_id);
struct iface *
iface_create(uint16_t type_id, uint32_t flags, uint16_t mtu, const char *name, void *info);
int iface_reconfig(
	uint16_t ifid,
	uint64_t set_attrs,
	uint32_t flags,
	uint16_t mtu,
	const char *name,
	void *info
);
int iface_destroy(uint16_t ifid);
struct iface *iface_from_id(uint16_t ifid);
int iface_get_eth_addr(uint16_t ifid, struct rte_ether_addr *);
uint16_t ifaces_count(uint16_t type_id);
struct iface *iface_next(uint16_t type_id, const struct iface *prev);

#define MAX_IFACES 1024

#endif
