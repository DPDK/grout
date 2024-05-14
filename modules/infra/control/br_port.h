// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_PORT
#define _BR_INFRA_PORT

#include <rte_mempool.h>

#include <stdint.h>
#include <sys/queue.h>

struct port {
	STAILQ_ENTRY(port) next;
	uint16_t port_id;
	uint16_t n_rxq;
	uint16_t rxq_size;
	uint16_t txq_size;
	struct rte_mempool *pool;
};

STAILQ_HEAD(ports, port);

extern struct ports ports;

int32_t port_create(const char *devargs);
int port_destroy(uint16_t port_id);
int port_reconfig(struct port *p);
struct port *find_port(uint16_t port_id);
uint32_t port_get_rxq_buffer_us(uint16_t port_id, uint16_t rxq_id);

#endif
