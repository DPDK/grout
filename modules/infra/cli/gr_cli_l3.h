// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_cli.h>
#include <gr_net_types.h>

#include <libsmartcols.h>

#include <sys/queue.h>

struct cli_route_ops {
	addr_family_t af;
	cmd_cb_t add;
	cmd_cb_t del;
	cmd_cb_t get;
	int (*list)(struct gr_api_client *, uint16_t vrf_id, struct libscols_table *);
	STAILQ_ENTRY(cli_route_ops) next;
};

struct cli_addr_ops {
	addr_family_t af;
	cmd_cb_t add;
	cmd_cb_t del;
	int (*list)(struct gr_api_client *, uint16_t iface_id, struct libscols_table *);
	int (*flush)(struct gr_api_client *, uint16_t iface_id);
	STAILQ_ENTRY(cli_addr_ops) next;
};

void cli_route_ops_register(struct cli_route_ops *);
void cli_addr_ops_register(struct cli_addr_ops *);
