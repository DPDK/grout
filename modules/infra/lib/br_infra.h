// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA
#define _BR_INFRA

#include <br_client.h>
#include <br_infra_types.h>

#include <stddef.h>

int br_infra_port_add(
	const struct br_client *,
	const char *name,
	const char *devargs,
	struct br_infra_port *port
);
int br_infra_port_del(const struct br_client *, const char *name);
int br_infra_port_get(const struct br_client *, const char *name, struct br_infra_port *);
int br_infra_port_list(
	const struct br_client *,
	size_t max_ports,
	struct br_infra_port *,
	size_t *n_ports
);

#endif
