// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include "iface.h"

#include <gr_bitops.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mempool.h>
#include <rte_spinlock.h>

#include <stdint.h>

typedef enum {
	MAC_FILTER_F_UNSUPP = GR_BIT8(0),
	MAC_FILTER_F_NOSPC = GR_BIT8(1),
} mac_filter_flags_t;

struct port_mac {
	uint16_t refcnt;
	struct rte_ether_addr mac;
};

GR_IFACE_INFO(GR_IFACE_TYPE_PORT, iface_info_port, {
	BASE(__gr_iface_info_port_base);

	uint16_t port_id;
	bool started;
	bool needs_reset;
	struct rte_mempool *pool;
	char *devargs;
	char *linux_ifname;
	uint32_t pool_size;
	bool virtio_offloads;
	uint64_t rx_offloads;
	rte_spinlock_t txq_locks[RTE_MAX_QUEUES_PER_PORT];
	struct {
		mac_filter_flags_t flags;
		unsigned hw_limit;
		unsigned count;
		struct port_mac macs[RTE_ETH_NUM_RECEIVE_MAC_ADDR];
	} filter;
});

const struct iface *port_get_iface(uint16_t port_id);

int port_mac_add(struct iface *, const struct rte_ether_addr *);
int port_mac_del(struct iface *, const struct rte_ether_addr *);
int port_promisc_set(struct iface *, bool enabled);
