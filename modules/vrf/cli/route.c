// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_net_types.h>
#include <gr_table.h>
#include <gr_vrf.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>

static cmd_status_t vrf_route_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_vrf_route_add_req req = {.exist_ok = true, .origin = GR_NH_ORIGIN_USER};

	if (arg_ip6_net(p, "DEST6", &req.r.key.dest6, true) >= 0)
		req.r.key.is_dest6 = true;
	else if (arg_ip4_net(p, "DEST4", &req.r.key.dest4, true) >= 0)
		req.r.key.is_dest6 = false;
	else
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.r.key.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (arg_u16(p, "VRF_OUT", &req.r.out_vrf_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_VRF_ROUTE_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t vrf_route_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_vrf_route_del_req req = {.key.vrf_id = 0, .missing_ok = true};

	if (arg_ip6_net(p, "DEST6", &req.key.dest6, true) >= 0)
		req.key.is_dest6 = true;
	else if (arg_ip4_net(p, "DEST4", &req.key.dest4, true) >= 0)
		req.key.is_dest6 = false;
	else
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.key.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_VRF_ROUTE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t vrf_route_show(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_vrf_route_list_req req = {.vrf_id = UINT16_MAX};
	struct libscols_table *table = scols_new_table();
	struct gr_vrf_route_list_resp *resp;
	struct libscols_line *line;
	struct gr_vrf_route *r;
	void *resp_ptr = NULL;
	int ret, i;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	ret = gr_api_client_send_recv(c, GR_VRF_ROUTE_LIST, sizeof(req), &req, &resp_ptr);
	if (ret < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	scols_table_new_column(table, "vrf", 0, 0);
	scols_table_new_column(table, "match", 0, 0);
	scols_table_new_column(table, "out_vrf", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (i = 0; i < resp->n_route; i++) {
		line = scols_table_new_line(table, NULL);
		r = &resp->route[i];

		scols_line_sprintf(line, 0, "%u", r->key.vrf_id);
		if (r->key.is_dest6)
			scols_line_sprintf(
				line, 1, IP6_F "/%hhu", &r->key.dest6.ip, r->key.dest6.prefixlen
			);
		else
			scols_line_sprintf(
				line, 1, IP4_F "/%hhu", &r->key.dest4.ip, r->key.dest4.prefixlen
			);
		scols_line_sprintf(line, 2, "%u", r->out_vrf_id);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD, CTX_ARG("vrf", "Create vrf stack elements.")),
		"route DEST4|DEST6 [vrf VRF] VRF_OUT",
		vrf_route_add,
		"Add vrf route.",
		with_help("Ipv4 destination prefix to steer", ec_node_re("DEST4", IPV4_NET_RE)),
		with_help("Ipv6 destination prefix to steer", ec_node_re("DEST6", IPV6_NET_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10)),
		with_help(
			"Next L3 routing domain ID to visit.",
			ec_node_uint("VRF_OUT", 0, UINT16_MAX - 1, 10)
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_DEL, CTX_ARG("vrf", "Delete vrf stack elements.")),
		"route DEST4|DEST6 [vrf VRF]",
		vrf_route_del,
		"Delete vrf route.",
		with_help("Ipv4 destination prefix to steer", ec_node_re("DEST4", IPV4_NET_RE)),
		with_help("Ipv6 destination prefix to steer", ec_node_re("DEST6", IPV6_NET_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))

	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("vrf", "Show vrf stack elements.")),
		"route [vrf VRF]",
		vrf_route_show,
		"View all vrf route",
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))

	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "vrf_route",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
