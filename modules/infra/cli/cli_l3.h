// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include "cli.h"
#include "display.h"

#include <string.h>
#include <sys/queue.h>

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
