// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_cli.h>
#include <br_client.h>
#include <br_ip.h>
#include <br_ip_types.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <stdint.h>

static cmd_status_t nh4_add(const struct br_client *c, const struct ec_pnode *p) {
	struct br_ip_nh4 next_hop;
	uint64_t port_id;

	if (inet_pton(AF_INET, arg_str(p, "IP"), &next_hop.host) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	if (br_eth_addr_parse(arg_str(p, "MAC"), &next_hop.mac) < 0)
		return CMD_ERROR;
	if (arg_uint(p, "PORT_ID", &port_id) < 0)
		return CMD_ERROR;

	next_hop.port_id = port_id;

	if (br_ip_nh4_add(c, &next_hop, true) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t nh4_del(const struct br_client *c, const struct ec_pnode *p) {
	ip4_addr_t host;

	if (inet_pton(AF_INET, arg_str(p, "IP"), &host) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	if (br_ip_nh4_del(c, host, true) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t nh4_list(const struct br_client *c, const struct ec_pnode *p) {
	struct br_ip_nh4 *next_hops = NULL;
	char buf[BUFSIZ];
	size_t len = 0;

	(void)p;

	if (br_ip_nh4_list(c, &len, &next_hops) < 0)
		return CMD_ERROR;

	printf("%-16s  %-20s  %s\n", "HOST", "MAC", "PORT");
	for (size_t i = 0; i < len; i++) {
		const struct br_ip_nh4 *nh = &next_hops[i];
		inet_ntop(AF_INET, &nh->host, buf, sizeof(buf));
		printf("%-16s  " ETH_ADDR_FMT "     %u\n",
		       buf,
		       ETH_BYTES_SPLIT(nh->mac.bytes),
		       nh->port_id);
	}

	free(next_hops);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *node = NULL;

	node = CLI_COMMAND_CONTEXT(
		"nh4",
		"Manage IPv4 next hops.",
		CLI_COMMAND(
			"add IP mac MAC port PORT_ID",
			nh4_add,
			"Add a new next hop.",
			with_help("IPv4 address.", ec_node_re("IP", IPV4_RE)),
			with_help("Ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),
			with_help("Output port ID.", ec_node_uint("PORT_ID", 0, UINT16_MAX - 1, 10))
		),
		CLI_COMMAND(
			"del IP",
			nh4_del,
			"Delete a next hop.",
			with_help("IPv4 address.", ec_node_re("IP", IPV4_RE))
		),
		CLI_COMMAND("list", nh4_list, "List all next hops.")
	);
	if (node == NULL)
		goto fail;

	if (ec_node_or_add(root, node) < 0)
		goto fail;

	return 0;

fail:
	ec_node_free(node);
	return -1;
}

static struct br_cli_context ctx = {
	.name = "nh4",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
