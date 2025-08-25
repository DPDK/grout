// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_bitops.h>
#include <gr_infra.h>
#include <gr_vec.h>

#include <rte_ether.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

struct __rte_cache_aligned iface {
	BASE(__gr_iface_base);

	gr_vec const struct iface **subinterfaces;
	char *name;
	alignas(alignof(void *)) uint8_t info[/* size depends on type */];
};

#define IFACE_SET_ALL UINT64_C(0xffffffffffffffff)

typedef int (*iface_init_t)(struct iface *, const void *api_info);
typedef int (*iface_reconfig_t)(
	struct iface *,
	uint64_t set_attrs,
	const struct gr_iface *,
	const void *api_info
);
typedef int (*iface_fini_t)(struct iface *);
typedef int (*iface_eth_addr_get_t)(const struct iface *, struct rte_ether_addr *);
typedef int (*iface_eth_addr_filter_t)(struct iface *, const struct rte_ether_addr *);
typedef void (*iface_to_api_t)(void *api_info, const struct iface *);

struct iface_type {
	uint16_t id;
	size_t info_size;
	iface_init_t init;
	iface_reconfig_t reconfig;
	iface_fini_t fini;
	iface_eth_addr_get_t get_eth_addr;
	iface_eth_addr_filter_t add_eth_addr;
	iface_eth_addr_filter_t del_eth_addr;
	iface_to_api_t to_api;
	const char *name;
	STAILQ_ENTRY(iface_type) next;
};

void iface_type_register(struct iface_type *);
struct iface_type *iface_type_get(gr_iface_type_t type_id);
struct iface *iface_create(const struct gr_iface *conf, const void *api_info);
int iface_reconfig(
	uint16_t ifid,
	uint64_t set_attrs,
	const struct gr_iface *conf,
	const void *api_info
);
int iface_destroy(uint16_t ifid);
struct iface *iface_from_id(uint16_t ifid);
void iface_add_subinterface(struct iface *parent, const struct iface *sub);
void iface_del_subinterface(struct iface *parent, const struct iface *sub);
int iface_get_eth_addr(uint16_t ifid, struct rte_ether_addr *);
int iface_add_eth_addr(uint16_t ifid, const struct rte_ether_addr *);
int iface_del_eth_addr(uint16_t ifid, const struct rte_ether_addr *);
uint16_t ifaces_count(gr_iface_type_t type_id);
struct iface *iface_next(gr_iface_type_t type_id, const struct iface *prev);

struct iface *get_vrf_iface(uint16_t vrf_id);
struct iface *iface_loopback_create(uint16_t vrf_id);
int iface_loopback_delete(uint16_t vrf_id);

struct __rte_cache_aligned iface_stats {
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};

#define MAX_IFACES 1024
#define MAX_VRFS 256

extern struct iface_stats iface_stats[MAX_IFACES][RTE_MAX_LCORE];
static inline struct iface_stats *iface_get_stats(uint16_t lcore_id, uint16_t ifid) {
	return &iface_stats[ifid][lcore_id];
}
