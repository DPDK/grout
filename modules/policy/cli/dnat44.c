// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_cli_nexthop.h>
#include <gr_display.h>
#include <gr_nat.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <stdint.h>

static cmd_status_t dnat44_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_dnat44_add_req req = {.exist_ok = true};

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.policy.iface_id) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "DEST", &req.policy.match) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "REPLACE", &req.policy.replace) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_DNAT44_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dnat44_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_dnat44_del_req req = {.missing_ok = true};

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "DEST", &req.match) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_DNAT44_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dnat44_list(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_dnat44_list_req req = {0};
	const struct gr_dnat44_policy *pol;
	int ret;

	if (arg_str(p, "VRF") != NULL && arg_vrf(c, p, "VRF", &req.vrf_id) < 0)
		return CMD_ERROR;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "INTERFACE", GR_DISP_LEFT); // 0
	gr_table_column(table, "DESTINATION", GR_DISP_LEFT); // 1
	gr_table_column(table, "REPLACE", GR_DISP_LEFT); // 2

	gr_api_client_stream_foreach (pol, ret, c, GR_DNAT44_LIST, sizeof(req), &req) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, pol->iface_id));
		gr_table_cell(table, 1, IP4_F, &pol->match);
		gr_table_cell(table, 2, IP4_F, &pol->replace);

		if (gr_table_print_row(table) < 0)
			continue;
	}

	gr_table_free(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static void add_columns_dnat(struct gr_table *table) {
	gr_table_column(table, "MATCH", GR_DISP_LEFT);
	gr_table_column(table, "REPLACE", GR_DISP_LEFT);
}

static void fill_table_dnat(struct gr_table *table, unsigned start_col, const void *info) {
	const struct gr_nexthop_info_dnat *dnat = info;
	gr_table_cell(table, start_col, IP4_F, &dnat->match);
	gr_table_cell(table, start_col + 1, IP4_F, &dnat->replace);
}

static void fill_object_dnat(struct gr_object *o, const void *info) {
	const struct gr_nexthop_info_dnat *dnat = info;
	gr_object_field(o, "match", 0, IP4_F, &dnat->match);
	gr_object_field(o, "replace", 0, IP4_F, &dnat->replace);
}

static struct cli_nexthop_formatter dnat_formatter = {
	.name = "dnat",
	.type = GR_NH_T_DNAT,
	.add_columns = add_columns_dnat,
	.fill_table = fill_table_dnat,
	.fill_object = fill_object_dnat,
};

#define DNAT_CTX(root) CLI_CONTEXT(root, CTX_ARG("dnat44", "Static destination NAT44."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		DNAT_CTX(root),
		"add interface IFACE destination DEST replace REPLACE",
		dnat44_add,
		"Create a DNAT44 rule.",
		with_help("Input interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Destination IPv4 address to match.", ec_node_re("DEST", IPV4_RE)),
		with_help("Replace match with this IPv4 address.", ec_node_re("REPLACE", IPV4_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		DNAT_CTX(root),
		"del interface IFACE destination DEST",
		dnat44_del,
		"Delete a DNAT44 rule.",
		with_help("Input interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Destination IPv4 address to match.", ec_node_re("DEST", IPV4_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		DNAT_CTX(root),
		"[show] [vrf VRF]",
		dnat44_list,
		"Display DNAT44 rules.",
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "dnat44",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_nexthop_formatter_register(&dnat_formatter);
}
