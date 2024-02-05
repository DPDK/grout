// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_PORT
#define _BR_INFRA_PORT

#include <rte_mempool.h>

#include <stdint.h>
#include <sys/queue.h>

struct port {
	LIST_ENTRY(port) next;
	uint16_t port_id;
	uint16_t burst;
	struct rte_mempool *pool;
};

LIST_HEAD(ports, port);

extern struct ports ports;

uint16_t port_get_burst_size(uint16_t port_id);

#endif
