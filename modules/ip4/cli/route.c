// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_cli.h>
#include <br_client.h>
#include <br_ip4.h>
#include <br_ip4_types.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <errno.h>

static cmd_status_t route4_add(const struct br_client *c, const struct ec_pnode *p) {
	struct ip4_net dest;
	ip4_addr_t next_hop;

	if (br_ip4_net_parse(arg_str(p, "DEST"), &dest, true) < 0)
		return CMD_ERROR;
	if (inet_pton(AF_INET, arg_str(p, "NH"), &next_hop) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	if (br_ip4_route_add(c, &dest, next_hop, true) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route4_del(const struct br_client *c, const struct ec_pnode *p) {
	struct ip4_net dest;

	if (br_ip4_net_parse(arg_str(p, "DEST"), &dest, true) < 0)
		return CMD_ERROR;

	if (br_ip4_route_del(c, &dest, true) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route4_get(const struct br_client *c, const struct ec_pnode *p) {
	struct br_ip4_nh nh;
	char buf[BUFSIZ];
	ip4_addr_t dest;

	if (inet_pton(AF_INET, arg_str(p, "DEST"), &dest) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	if (br_ip4_route_get(c, dest, &nh) < 0)
		return CMD_ERROR;

	printf("%-16s  %-20s  %s\n", "GATEWAY", "MAC", "PORT");
	inet_ntop(AF_INET, &nh.host, buf, sizeof(buf));
	printf("%-16s  " ETH_ADDR_FMT "     %u\n", buf, ETH_BYTES_SPLIT(nh.mac.bytes), nh.port_id);

	return CMD_SUCCESS;
}

static cmd_status_t route4_list(const struct br_client *c, const struct ec_pnode *p) {
	struct br_ip4_route *routes = NULL;
	char dest[BUFSIZ], nh[BUFSIZ];
	size_t len = 0;

	(void)p;

	if (br_ip4_route_list(c, &len, &routes) < 0)
		return CMD_ERROR;

	printf("%-20s  %s\n", "DESTINATION", "NEXT_HOP");
	for (size_t i = 0; i < len; i++) {
		const struct br_ip4_route *route = &routes[i];
		br_ip4_net_format(&route->dest, dest, sizeof(dest));
		inet_ntop(AF_INET, &route->nh, nh, sizeof(nh));
		printf("%-20s  %s\n", dest, nh);
	}

	free(routes);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *ipv4 = cli_context(root, "ipv4", "Manage IPv4.");
	struct ec_node *route = cli_context(ipv4, "route", "Manage IPv4 routes.");
	int ret;

	if (ipv4 == NULL || route == NULL)
		return -1;

	ret = CLI_COMMAND(
		route,
		"add DEST via NH",
		route4_add,
		"Add a new route.",
		with_help("IPv4 destination prefix.", ec_node_re("DEST", IPV4_NET_RE)),
		with_help("IPv4 next hop address.", ec_node_re("NH", IPV4_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		route,
		"del DEST",
		route4_del,
		"Delete a route.",
		with_help("IPv4 destination prefix.", ec_node_re("DEST", IPV4_NET_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		route,
		"get DEST",
		route4_get,
		"Get the next hop that would be taken for a destination address.",
		with_help("IPv4 destination address.", ec_node_re("DEST", IPV4_RE))
	);
	if (ret < 0)
		return ret;
	return CLI_COMMAND(route, "list", route4_list, "List all routes.");
}

static struct br_cli_context ctx = {
	.name = "ipv4 route",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
