// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_ip4.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>

static cmd_status_t route4_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_route_add_req req = {.exist_ok = true, .origin = GR_NH_ORIGIN_USER};

	if (arg_ip4_net(p, "DEST", &req.dest, true) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "NH", &req.nh) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "ID", &req.nh_id) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP4_ROUTE_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route4_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_route_del_req req = {.missing_ok = true};

	if (arg_ip4_net(p, "DEST", &req.dest, true) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP4_ROUTE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route4_list(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_route_list_req req = {.vrf_id = UINT16_MAX};
	struct libscols_table *table = scols_new_table();
	const struct gr_ip4_route_list_resp *resp;
	void *resp_ptr = NULL;

	if (table == NULL)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP4_ROUTE_LIST, sizeof(req), &req, &resp_ptr) < 0) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	resp = resp_ptr;
	scols_table_new_column(table, "VRF", 0, 0);
	scols_table_new_column(table, "DESTINATION", 0, 0);
	scols_table_new_column(table, "NEXT_HOP", 0, 0);
	scols_table_new_column(table, "ORIGIN", 0, 0);
	scols_table_new_column(table, "ID", 0, 0);
	scols_table_new_column(table, "NEXT_HOP_VRF", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_routes; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct gr_ip4_route *route = &resp->routes[i];
		struct gr_iface iface;
		scols_line_sprintf(line, 0, "%u", route->vrf_id);
		scols_line_sprintf(line, 1, IP4_F "/%hhu", &route->dest.ip, route->dest.prefixlen);
		switch (route->nh.af) {
		case GR_AF_UNSPEC:
			if (iface_from_id(c, route->nh.iface_id, &iface) < 0)
				scols_line_sprintf(line, 2, "%u", route->nh.iface_id);
			else
				scols_line_sprintf(line, 2, "%s", iface.name);
			break;
		case GR_AF_IP4:
			scols_line_sprintf(line, 2, IP4_F, &route->nh.ipv4);
			break;
		case GR_AF_IP6:
			scols_line_sprintf(line, 2, IP6_F, &route->nh.ipv6);
			break;
		}
		scols_line_sprintf(line, 3, "%s", gr_nh_origin_name(route->origin));
		if (route->nh.nh_id != GR_NH_ID_UNSET)
			scols_line_sprintf(line, 4, "%u", route->nh.nh_id);
		else
			scols_line_set_data(line, 4, "");
		scols_line_sprintf(line, 5, "%u", route->nh.vrf_id);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t route4_get(const struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_ip4_route_get_resp *resp;
	struct gr_ip4_route_get_req req = {0};
	struct gr_iface iface;
	void *resp_ptr = NULL;

	if (arg_ip4(p, "DEST", &req.dest) < 0) {
		if (errno == ENOENT)
			return route4_list(c, p);
		return CMD_ERROR;
	}
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP4_ROUTE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf(IP4_F " via " IP4_F " lladdr " ETH_F, &req.dest, &resp->nh.ipv4, &resp->nh.mac);
	if (resp->nh.nh_id != GR_NH_ID_UNSET)
		printf(" id %u", resp->nh.nh_id);
	if (iface_from_id(c, resp->nh.iface_id, &iface) == 0)
		printf(" iface %s", iface.name);
	else
		printf(" iface %u", resp->nh.iface_id);
	printf("\n");
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		IP_ADD_CTX(root),
		"route DEST via (NH)|(id ID) [vrf VRF]",
		route4_add,
		"Add a new route.",
		with_help("IPv4 destination prefix.", ec_node_re("DEST", IPV4_NET_RE)),
		with_help("IPv4 next hop address.", ec_node_re("NH", IPV4_RE)),
		with_help("Next hop user ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP_DEL_CTX(root),
		"route DEST [vrf VRF]",
		route4_del,
		"Delete a route.",
		with_help("IPv4 destination prefix.", ec_node_re("DEST", IPV4_NET_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP_SHOW_CTX(root),
		"route [(destination DEST),(vrf VRF)]",
		route4_get,
		"Show IPv4 routes.",
		with_help("IPv4 destination address.", ec_node_re("DEST", IPV4_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "ipv4 route",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
