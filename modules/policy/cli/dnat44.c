// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "policy.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_nat.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <stdint.h>

static cmd_status_t dnat44_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface *iface = iface_from_name(c, arg_str(p, "IFACE"));
	struct gr_dnat44_add_req req = {.exist_ok = true};

	if (iface == NULL)
		return CMD_ERROR;
	req.policy.iface_id = iface->id;
	free(iface);

	if (arg_ip4(p, "DEST", &req.policy.match) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "REPLACE", &req.policy.replace) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_DNAT44_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dnat44_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface *iface = iface_from_name(c, arg_str(p, "IFACE"));
	struct gr_dnat44_del_req req = {.missing_ok = true};

	if (iface == NULL)
		return CMD_ERROR;
	req.iface_id = iface->id;
	free(iface);

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

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "INTERFACE", 0, 0);
	scols_table_new_column(table, "DESTINATION", 0, 0);
	scols_table_new_column(table, "REPLACE", 0, 0);
	scols_table_set_column_separator(table, "  ");

	gr_api_client_stream_foreach (pol, ret, c, GR_DNAT44_LIST, sizeof(req), &req) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		struct gr_iface *iface = iface_from_id(c, pol->iface_id);

		if (iface == NULL)
			scols_line_sprintf(line, 0, "%u", pol->iface_id);
		else
			scols_line_sprintf(line, 0, "%s", iface->name);
		free(iface);

		scols_line_sprintf(line, 1, IP4_F, &pol->match);
		scols_line_sprintf(line, 2, IP4_F, &pol->replace);
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		POLICY_ADD_CTX(root),
		"dnat44 interface IFACE destination DEST replace REPLACE",
		dnat44_add,
		"Create a DNAT44 rule.",
		with_help("Input interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Destination IPv4 address to match.", ec_node_re("DEST", IPV4_RE)),
		with_help("Replace match with this IPv4 address.", ec_node_re("REPLACE", IPV4_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		POLICY_DEL_CTX(root),
		"dnat44 interface IFACE destination DEST",
		dnat44_del,
		"Delete a DNAT44 rule.",
		with_help("Input interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Destination IPv4 address to match.", ec_node_re("DEST", IPV4_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		POLICY_SHOW_CTX(root),
		"dnat44 [vrf VRF]",
		dnat44_list,
		"Display DNAT44 rules.",
		with_help("L3 addressing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "nat44",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
