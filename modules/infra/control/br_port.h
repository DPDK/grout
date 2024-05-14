// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_PORT
#define _BR_INFRA_PORT

#include <br_iface.h>

#include <rte_ether.h>
#include <rte_mempool.h>

#include <stdint.h>
#include <sys/queue.h>

// Value for iface.type
#define IFACE_TYPE_PORT 0x0001

// Port reconfig attributes
#define PORT_SET_N_RXQS BR_BIT64(32)
#define PORT_SET_N_TXQS BR_BIT64(33)
#define PORT_SET_Q_SIZE BR_BIT64(34)
#define PORT_SET_MAC BR_BIT64(35)

struct iface_info_port {
	uint16_t port_id;
	uint8_t n_rxq;
	uint8_t n_txq;
	bool configured;
	uint16_t rxq_size;
	uint16_t txq_size;
	struct rte_ether_addr mac;
	struct rte_mempool *pool;
	char devargs[64];
};

uint32_t port_get_rxq_buffer_us(uint16_t port_id, uint16_t rxq_id);
int iface_port_reconfig(struct iface *iface, uint64_t set_attrs, void *new_info);
const struct iface *port_get_iface(uint16_t port_id);

#endif
