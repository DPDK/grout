// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA
#define _BR_INFRA

#include <br_client.h>
#include <br_infra_types.h>

#include <stddef.h>

int br_infra_port_add(const struct br_client *, const char *devargs, uint16_t *port_id);
int br_infra_port_del(const struct br_client *, uint16_t port_id);
int br_infra_port_get(const struct br_client *, uint16_t port_id, struct br_infra_port *);
int br_infra_port_list(const struct br_client *, size_t *n_ports, struct br_infra_port **);
int br_infra_port_set(const struct br_client *, uint16_t port_id, uint16_t n_rxq);

#endif
