// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_PORT_CONFIG
#define _BR_PORT_CONFIG

#include "port.h"

int port_destroy(uint16_t port_id, struct port_entry *);

int port_reconfig(struct port_entry *, uint16_t n_rxq, uint16_t n_txq);

#endif
