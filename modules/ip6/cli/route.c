// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_event.h>
#include <gr_cli_iface.h>
#include <gr_cli_nexthop.h>
#include <gr_ip6.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>

static cmd_status_t route6_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_route_add_req req = {.exist_ok = true, .origin = GR_NH_ORIGIN_USER};

	if (arg_ip6_net(p, "DEST", &req.dest, true) < 0)
		return CMD_ERROR;
	if (arg_ip6(p, "NH", &req.nh) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "ID", &req.nh_id) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_ROUTE_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route6_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_route_del_req req = {.missing_ok = true};

	if (arg_ip6_net(p, "DEST", &req.dest, true) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_ROUTE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route6_list(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_route_list_req req = {.vrf_id = GR_VRF_ID_ALL};
	const struct gr_ip6_route *route;
	char buf[128];
	int ret;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "VRF", 0, 0);
	scols_table_new_column(table, "DESTINATION", 0, 0);
	scols_table_new_column(table, "NEXT_HOP", 0, 0);
	scols_table_set_column_separator(table, "  ");

	gr_api_client_stream_foreach (route, ret, c, GR_IP6_ROUTE_LIST, sizeof(req), &req) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		scols_line_sprintf(line, 0, "%u", route->vrf_id);
		scols_line_sprintf(line, 1, IP6_F "/%hhu", &route->dest, route->dest.prefixlen);
		if (cli_nexthop_format(buf, sizeof(buf), c, &route->nh, true) > 0)
			scols_line_set_data(line, 2, buf);
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t route6_get(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_ip6_route_get_resp *resp;
	struct gr_ip6_route_get_req req = {0};
	void *resp_ptr = NULL;
	char buf[128];

	if (arg_ip6(p, "DEST", &req.dest) < 0)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_ROUTE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	buf[0] = '\0';
	cli_nexthop_format(buf, sizeof(buf), c, &resp->nh, true);
	printf(IP6_F " via %s\n", &req.dest, buf);
	free(resp_ptr);

	return CMD_SUCCESS;
}

#define ROUTE6_CTX(root) CLI_CONTEXT(root, CTX_ARG("route6", "IPv6 routing table."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		ROUTE6_CTX(root),
		"add DEST via (NH)|(id ID) [vrf VRF]",
		route6_add,
		"Add a new route.",
		with_help("IPv6 destination prefix.", ec_node_re("DEST", IPV6_NET_RE)),
		with_help("IPv6 next hop address.", ec_node_re("NH", IPV6_RE)),
		with_help("Next hop user ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		ROUTE6_CTX(root),
		"del DEST [vrf VRF]",
		route6_del,
		"Delete a route.",
		with_help("IPv6 destination prefix.", ec_node_re("DEST", IPV6_NET_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		ROUTE6_CTX(root),
		"show [vrf VRF]",
		route6_list,
		"Show IPv6 routes.",
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		ROUTE6_CTX(root),
		"get DEST [vrf VRF]",
		route6_get,
		"Get the route associated with a destination IPv6 address.",
		with_help("IPv6 destination address.", ec_node_re("DEST", IPV6_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "ipv6 route",
	.init = ctx_init,
};

static void route_event_print(uint32_t event, const void *obj) {
	const struct gr_ip6_route *r = obj;
	const char *action;
	char buf[128];

	switch (event) {
	case GR_EVENT_IP6_ROUTE_ADD:
		action = "add";
		break;
	case GR_EVENT_IP6_ROUTE_DEL:
		action = "del";
		break;
	default:
		action = "?";
		break;
	}

	buf[0] = '\0';
	cli_nexthop_format(buf, sizeof(buf), NULL, &r->nh, true);
	printf("route6 %s: vrf=%u " IP6_F "/%hhu via %s\n",
	       action,
	       r->vrf_id,
	       &r->dest.ip,
	       r->dest.prefixlen,
	       buf);
}

static struct cli_event_printer printer = {
	.print = route_event_print,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IP6_ROUTE_ADD,
		GR_EVENT_IP6_ROUTE_DEL,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_event_printer_register(&printer);
}
