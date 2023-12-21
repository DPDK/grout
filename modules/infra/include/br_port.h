// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_PORT
#define _BR_INFRA_PORT

#include <rte_mempool.h>

#include <stdint.h>
#include <sys/queue.h>

struct port {
	LIST_ENTRY(port) next;
	uint16_t port_id;
	struct rte_mempool *pool;
};

LIST_HEAD(ports, port);

extern struct ports ports;

#endif
