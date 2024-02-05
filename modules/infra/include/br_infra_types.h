// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_TYPES
#define _BR_INFRA_TYPES

#include <br_api.h>
#include <br_net_types.h>

#include <sched.h>
#include <stdint.h>
#include <sys/types.h>

struct br_infra_port {
	uint16_t index;
	char device[128];
	uint16_t n_rxq;
	uint16_t n_txq;
	uint16_t burst;
	struct eth_addr mac;
};

struct br_infra_rxq {
	uint16_t port_id;
	uint16_t rxq;
};

typedef enum {
	BR_INFRA_WORKER_CPU_ID = BR_BIT32(0),
	BR_INFRA_WORKER_RXQS = BR_BIT32(1),
} br_infra_worker_attr_t;

struct br_infra_worker {
	uint64_t worker_id;
	uint16_t cpu_id;
	uint8_t n_rx_queues;
	struct br_infra_rxq rx_queues[32];
};

#endif
