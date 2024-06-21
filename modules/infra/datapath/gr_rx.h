// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_RX
#define _GR_INFRA_RX

#include <stdint.h>

struct rx_port_queue {
	uint16_t port_id;
	uint16_t rxq_id;
};

struct rx_node_queues {
	uint16_t n_queues;
	struct rx_port_queue queues[/* n_queues */];
};

#endif
