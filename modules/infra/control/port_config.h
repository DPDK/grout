// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_PORT_CONFIG
#define _BR_PORT_CONFIG

#include <br_port.h>

int port_destroy(uint16_t port_id, struct port *);

int port_reconfig(struct port *, uint16_t n_rxq);

#endif
