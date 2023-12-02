// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_PORT_CONFIG
#define _BR_INFRA_PORT_CONFIG

#include <stdint.h>
#include <sys/queue.h>

struct port_entry {
	uint16_t port_id;
	struct rte_mempool *pool;
	char name[64];
	LIST_ENTRY(port_entry) entries;
};

#endif
