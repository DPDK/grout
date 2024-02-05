// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_BROADCAST
#define _BR_INFRA_BROADCAST

#include <stdint.h>

struct broadcast_node_ports {
	uint16_t n_ports;
	uint16_t port_ids[/* n_ports */];
};

#endif
