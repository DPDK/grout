// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include "cli.h"
#include "cli_iface.h"
#include "display.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

// Fetch the interfaces a local address is exposed on and fill a table cell with
// their comma-separated names. `req` identifies the address (its owning
// interface and value) and `req_type` is the address family EXPOSE_LIST request
// which streams the exposed interface ids.
static inline void cli_expose_cell(
	struct gr_api_client *c,
	struct gr_table *table,
	unsigned col,
	uint32_t req_type,
	size_t req_len,
	const void *req
) {
	const uint16_t *id;
	char buf[256];
	size_t n = 0;
	int ret;

	gr_api_client_stream_foreach (id, ret, c, req_type, req_len, req)
		SAFE_BUF(
			snprintf, sizeof(buf), "%s%s", n > 0 ? "," : "", iface_name_from_id(c, *id)
		);
err:
	gr_table_cell(table, col, "%s", n > 0 ? buf : "");
}

#define CLI_FAMILY_NODE(ipv4_help, ipv6_help)                                                      \
	with_help(                                                                                 \
		"Address family.",                                                                 \
		EC_NODE_OR(                                                                        \
			"FAMILY",                                                                  \
			with_help(ipv4_help, ec_node_str("ipv4", "ipv4")),                         \
			with_help(ipv6_help, ec_node_str("ipv6", "ipv6"))                          \
		)                                                                                  \
	)

static inline addr_family_t cli_parse_family(const struct ec_pnode *p) {
	const char *family = arg_str(p, "FAMILY");

	if (family != NULL) {
		if (strncmp(family, "ipv4", sizeof("ipv4")) == 0)
			return GR_AF_IP4;
		if (strncmp(family, "ipv6", sizeof("ipv6")) == 0)
			return GR_AF_IP6;
	}

	return GR_AF_UNSPEC;
}

struct cli_route_ops {
	addr_family_t af;
	cmd_cb_t add;
	cmd_cb_t del;
	cmd_cb_t get;
	int (*list)(struct gr_api_client *, uint16_t vrf_id, struct gr_table *, uint16_t max);
	cmd_cb_t config_set;
	int (*config_show)(struct gr_api_client *, uint16_t vrf_id, struct gr_table *);
	STAILQ_ENTRY(cli_route_ops) next;
};

struct cli_addr_ops {
	addr_family_t af;
	cmd_cb_t add;
	cmd_cb_t del;
	cmd_cb_t expose;
	cmd_cb_t unexpose;
	int (*list)(struct gr_api_client *, uint16_t iface_id, struct gr_table *);
	int (*flush)(struct gr_api_client *, uint16_t iface_id);
	STAILQ_ENTRY(cli_addr_ops) next;
};

struct cli_icmp_ops {
	addr_family_t af;
	cmd_cb_t ping;
	cmd_cb_t traceroute;
	STAILQ_ENTRY(cli_icmp_ops) next;
};

void cli_route_ops_register(struct cli_route_ops *);
void cli_addr_ops_register(struct cli_addr_ops *);
void cli_icmp_ops_register(struct cli_icmp_ops *);
