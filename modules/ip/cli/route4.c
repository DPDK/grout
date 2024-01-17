// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#include <br_cli.h>
#include <br_client.h>
#include <br_ip.h>
#include <br_ip_types.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <errno.h>

static cmd_status_t route4_add(const struct br_client *c, const struct ec_pnode *p) {
	struct ip4_net dest;
	ip4_addr_t next_hop;

	if (br_ip4_net_parse(arg_str(p, "DEST"), &dest) < 0)
		return CMD_ERROR;
	if (inet_pton(AF_INET, arg_str(p, "NH"), &next_hop) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	if (br_ip_route4_add(c, &dest, next_hop, true) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route4_del(const struct br_client *c, const struct ec_pnode *p) {
	struct ip4_net dest;

	if (br_ip4_net_parse(arg_str(p, "DEST"), &dest) < 0)
		return CMD_ERROR;

	if (br_ip_route4_del(c, &dest, true) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route4_list(const struct br_client *c, const struct ec_pnode *p) {
	struct br_ip_route4 *routes = NULL;
	char dest[BUFSIZ], nh[BUFSIZ];
	size_t len = 0;

	(void)p;

	if (br_ip_route4_list(c, &len, &routes) < 0)
		return CMD_ERROR;

	printf("%-20s  %s\n", "DESTINATION", "NEXT_HOP");
	for (size_t i = 0; i < len; i++) {
		const struct br_ip_route4 *route = &routes[i];
		br_ip4_net_format(&route->dest, dest, sizeof(dest));
		inet_ntop(AF_INET, &route->nh, nh, sizeof(nh));
		printf("%-20s  %s\n", dest, nh);
	}

	free(routes);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *node = NULL;

	node = CLI_COMMAND_CONTEXT(
		"route4",
		"Manage IPv4 routes.",
		CLI_COMMAND(
			"add DEST via NH",
			route4_add,
			"Add a new route.",
			with_help("IPv4 destination prefix.", ec_node_re("DEST", IPV4_NET_RE)),
			with_help("IPv4 next hop address.", ec_node_re("NH", IPV4_RE))
		),
		CLI_COMMAND(
			"del DEST",
			route4_del,
			"Delete a route.",
			with_help("IPv4 destination prefix.", ec_node_re("DEST", IPV4_NET_RE))
		),
		CLI_COMMAND("list", route4_list, "List all routes.")
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
	.name = "route4",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
