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

	gr_vec struct iface **subinterfaces;
	char *name;
	alignas(alignof(void *)) uint8_t info[/* size depends on type */];
};

#define GR_IFACE_INFO(type_id, type_name, fields)                                                  \
	struct type_name fields __attribute__((__may_alias__, aligned(alignof(void *))));          \
	static inline struct type_name *type_name(const struct iface *iface) {                     \
		assert(iface->type == type_id);                                                    \
		return (struct type_name *)iface->info;                                            \
	}

#define IFACE_SET_ALL UINT64_C(0xffffffffffffffff)

struct iface_type {
	uint16_t id;
	size_t pub_size;
	size_t priv_size;
	int (*init)(struct iface *, const void *api_info);
	int (*reconfig)(
		struct iface *,
		uint64_t set_attrs,
		const struct gr_iface *,
		const void *api_info
	);
	int (*fini)(struct iface *);
	int (*get_eth_addr)(const struct iface *, struct rte_ether_addr *);
	int (*set_eth_addr)(struct iface *, const struct rte_ether_addr *);
	int (*add_eth_addr)(struct iface *, const struct rte_ether_addr *);
	int (*del_eth_addr)(struct iface *, const struct rte_ether_addr *);
	int (*set_up_down)(struct iface *, bool up);
	int (*set_mtu)(struct iface *, uint16_t mtu);
	int (*set_promisc)(struct iface *, bool enabled);
	int (*set_allmulti)(struct iface *, bool enabled);
	int (*add_vlan)(struct iface *, uint16_t vlan_id);
	int (*del_vlan)(struct iface *, uint16_t vlan_id);
	void (*to_api)(void *api_info, const struct iface *);
	const char *name;
	STAILQ_ENTRY(iface_type) next;
};

void iface_type_register(struct iface_type *);
const struct iface_type *iface_type_get(gr_iface_type_t type_id);
struct iface *iface_create(const struct gr_iface *conf, const void *api_info);
int iface_reconfig(
	uint16_t ifid,
	uint64_t set_attrs,
	const struct gr_iface *conf,
	const void *api_info
);
int iface_destroy(uint16_t ifid);
struct iface *iface_from_id(uint16_t ifid);
void iface_add_subinterface(struct iface *parent, struct iface *sub);
void iface_del_subinterface(struct iface *parent, struct iface *sub);
int iface_get_eth_addr(uint16_t ifid, struct rte_ether_addr *);
int iface_set_eth_addr(uint16_t ifid, const struct rte_ether_addr *);
int iface_add_eth_addr(uint16_t ifid, const struct rte_ether_addr *);
int iface_del_eth_addr(uint16_t ifid, const struct rte_ether_addr *);
int iface_set_mtu(uint16_t ifid, uint16_t mtu);
int iface_set_up_down(uint16_t ifid, bool up);
int iface_set_promisc(uint16_t ifid, bool enabled);
int iface_set_allmulti(uint16_t ifid, bool enabled);
int iface_add_vlan(uint16_t ifid, uint16_t vlan_id);
int iface_del_vlan(uint16_t ifid, uint16_t vlan_id);
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

extern struct iface_stats iface_stats[MAX_IFACES][RTE_MAX_LCORE];
static inline struct iface_stats *iface_get_stats(uint16_t lcore_id, uint16_t ifid) {
	return &iface_stats[ifid][lcore_id];
}
