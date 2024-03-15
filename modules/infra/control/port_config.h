// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_PORT_CONFIG
#define _BR_PORT_CONFIG

#include <br_port.h>

int port_destroy(uint16_t port_id, struct port *);

int port_reconfig(struct port *);

#endif
