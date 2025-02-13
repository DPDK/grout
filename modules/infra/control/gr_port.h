// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_INFRA_PORT
#define _GR_INFRA_PORT

#include <gr_bitops.h>
#include <gr_iface.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mempool.h>

#include <stdint.h>
#include <sys/queue.h>

enum {
	MAC_FILTER_F_UNSUPP = GR_BIT8(0),
	MAC_FILTER_F_NOSPC = GR_BIT8(1),
	MAC_FILTER_F_ALL = GR_BIT8(2),
};

struct mac_filter {
	uint8_t flags;
	uint8_t count;
	uint8_t hw_limit;
	uint16_t refcnt[RTE_ETH_NUM_RECEIVE_MAC_ADDR];
	struct rte_ether_addr mac[RTE_ETH_NUM_RECEIVE_MAC_ADDR];
};

struct __rte_aligned(alignof(void *)) iface_info_port {
	uint16_t port_id;
	uint8_t n_rxq;
	uint8_t n_txq;
	bool configured;
	uint16_t rxq_size;
	uint16_t txq_size;
	struct rte_ether_addr mac;
	struct rte_mempool *pool;
	char *devargs;
	uint32_t pool_size;
	struct mac_filter ucast_filter;
	struct mac_filter mcast_filter;
};

uint32_t port_get_rxq_buffer_us(uint16_t port_id, uint16_t rxq_id);
int iface_port_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *conf,
	const void *api_info
);
const struct iface *port_get_iface(uint16_t port_id);
#endif
