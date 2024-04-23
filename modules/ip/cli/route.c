// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip.h"

#include <br_api.h>
#include <br_cli.h>
#include <br_ip4.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <errno.h>

static cmd_status_t route4_add(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_ip4_route_add_req req = {.exist_ok = true};

	if (br_ip4_net_parse(arg_str(p, "DEST"), &req.dest, true) < 0)
		return CMD_ERROR;
	if (inet_pton(AF_INET, arg_str(p, "NH"), &req.nh) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	if (br_api_client_send_recv(c, BR_IP4_ROUTE_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route4_del(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_ip4_route_del_req req = {.missing_ok = true};

	if (br_ip4_net_parse(arg_str(p, "DEST"), &req.dest, true) < 0)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_IP4_ROUTE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route4_list(const struct br_api_client *c, const struct ec_pnode *p) {
	const struct br_ip4_route_list_resp *resp;
	char dest[BUFSIZ], nh[BUFSIZ];
	void *resp_ptr = NULL;

	(void)p;

	if (br_api_client_send_recv(c, BR_IP4_ROUTE_LIST, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("%-20s  %s\n", "DESTINATION", "NEXT_HOP");
	for (size_t i = 0; i < resp->n_routes; i++) {
		const struct br_ip4_route *route = &resp->routes[i];
		br_ip4_net_format(&route->dest, dest, sizeof(dest));
		inet_ntop(AF_INET, &route->nh, nh, sizeof(nh));
		printf("%-20s  %s\n", dest, nh);
	}

	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t route4_get(const struct br_api_client *c, const struct ec_pnode *p) {
	const struct br_ip4_route_get_resp *resp;
	struct br_ip4_route_get_req req;
	void *resp_ptr = NULL;
	char buf[BUFSIZ];
	const char *dest = arg_str(p, "DEST");

	if (dest == NULL) {
		if (errno == ENOENT)
			return route4_list(c, p);
		return CMD_ERROR;
	}
	if (inet_pton(AF_INET, dest, &req.dest) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	if (br_api_client_send_recv(c, BR_IP4_ROUTE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("%-16s  %-20s  %s\n", "GATEWAY", "MAC", "PORT");
	inet_ntop(AF_INET, &resp->nh.host, buf, sizeof(buf));
	printf("%-16s  " ETH_ADDR_FMT "     %u\n",
	       buf,
	       ETH_BYTES_SPLIT(resp->nh.mac.bytes),
	       resp->nh.port_id);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		IP_ADD_CTX(root),
		"route DEST via NH",
		route4_add,
		"Add a new route.",
		with_help("IPv4 destination prefix.", ec_node_re("DEST", IPV4_NET_RE)),
		with_help("IPv4 next hop address.", ec_node_re("NH", IPV4_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP_DEL_CTX(root),
		"route DEST",
		route4_del,
		"Delete a route.",
		with_help("IPv4 destination prefix.", ec_node_re("DEST", IPV4_NET_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP_SHOW_CTX(root),
		"route [DEST]",
		route4_get,
		"Show IPv4 routes.",
		with_help("IPv4 destination address.", ec_node_re("DEST", IPV4_RE))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct br_cli_context ctx = {
	.name = "ipv4 route",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
