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
	uint16_t rxq_size;
	uint16_t txq_size;
	struct eth_addr mac;
};

struct br_infra_rxq {
	uint16_t port_id;
	uint16_t rxq_id;
	uint16_t cpu_id;
	uint16_t enabled;
};

struct br_infra_stat {
	char name[64];
	uint64_t value;
};

struct br_infra_graph_stat {
	char node[64];
	uint64_t objects;
	uint64_t calls;
	uint64_t cycles;
};

#endif
