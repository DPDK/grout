// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_ip6.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>

static cmd_status_t route6_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_route_add_req req = {.exist_ok = true};

	if (ip6_net_parse(arg_str(p, "DEST"), &req.dest, true) < 0)
		return CMD_ERROR;
	if (inet_pton(AF_INET6, arg_str(p, "NH"), &req.nh) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_ROUTE_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route6_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_route_del_req req = {.missing_ok = true};

	if (ip6_net_parse(arg_str(p, "DEST"), &req.dest, true) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_ROUTE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route6_list(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_route_list_req req = {.vrf_id = UINT16_MAX};
	struct libscols_table *table = scols_new_table();
	const struct gr_ip6_route_list_resp *resp;
	char dest[BUFSIZ], nh[BUFSIZ];
	void *resp_ptr = NULL;

	if (table == NULL)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_ROUTE_LIST, sizeof(req), &req, &resp_ptr) < 0) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	resp = resp_ptr;
	scols_table_new_column(table, "VRF", 0, 0);
	scols_table_new_column(table, "DESTINATION", 0, 0);
	scols_table_new_column(table, "NEXT_HOP", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_routes; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct gr_ip6_route *route = &resp->routes[i];
		ip6_net_format(&route->dest, dest, sizeof(dest));
		inet_ntop(AF_INET6, &route->nh, nh, sizeof(nh));
		scols_line_sprintf(line, 0, "%u", route->vrf_id);
		scols_line_set_data(line, 1, dest);
		scols_line_set_data(line, 2, nh);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t route6_get(const struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_ip6_route_get_resp *resp;
	struct gr_ip6_route_get_req req = {0};
	struct gr_iface iface;
	void *resp_ptr = NULL;
	char buf[BUFSIZ];
	const char *dest = arg_str(p, "DEST");

	if (dest == NULL) {
		if (errno == ENOENT)
			return route6_list(c, p);
		return CMD_ERROR;
	}
	if (inet_pton(AF_INET6, dest, &req.dest) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_ROUTE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	inet_ntop(AF_INET6, &resp->nh.host, buf, sizeof(buf));
	printf("%s via %s lladdr " ETH_ADDR_FMT, dest, buf, ETH_ADDR_SPLIT(&resp->nh.mac));
	if (iface_from_id(c, resp->nh.iface_id, &iface) == 0)
		printf("iface %s", iface.name);
	else
		printf("iface %u", resp->nh.iface_id);
	printf("\n");
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		IP6_ADD_CTX(root),
		"route DEST via NH [vrf VRF]",
		route6_add,
		"Add a new route.",
		with_help("IPv6 destination prefix.", ec_node_re("DEST", IPV6_NET_RE)),
		with_help("IPv6 next hop address.", ec_node_re("NH", IPV6_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP6_DEL_CTX(root),
		"route DEST [vrf VRF]",
		route6_del,
		"Delete a route.",
		with_help("IPv6 destination prefix.", ec_node_re("DEST", IPV6_NET_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP6_SHOW_CTX(root),
		"route [(destination DEST),(vrf VRF)]",
		route6_get,
		"Show IPv6 routes.",
		with_help("IPv6 destination address.", ec_node_re("DEST", IPV6_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "ipv6 route",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
