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
});

const struct iface *port_get_iface(uint16_t port_id);
