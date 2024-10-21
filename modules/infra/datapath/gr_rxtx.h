// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_RXTX
#define _GR_INFRA_RXTX

#include <rte_build_config.h>

#include <stdint.h>

struct rx_port_queue {
	uint16_t port_id;
	uint16_t rxq_id;
};

struct rx_node_queues {
	uint16_t n_queues;
	struct rx_port_queue queues[/* n_queues */];
};

struct tx_node_queues {
	uint16_t txq_ids[RTE_MAX_ETHPORTS];
};

#endif
