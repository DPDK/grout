// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "ip.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_ip4.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <stdint.h>

static cmd_status_t dnat44_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_dnat44_add_req req = {.exist_ok = true};
	struct gr_iface iface;

	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;
	req.rule.iface_id = iface.id;
	if (arg_ip4(p, "DEST", &req.rule.match) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "REPLACE", &req.rule.replace) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_DNAT44_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dnat44_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_dnat44_del_req req = {.missing_ok = true};
	struct gr_iface iface;

	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;
	req.iface_id = iface.id;
	if (arg_ip4(p, "DEST", &req.match) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_DNAT44_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dnat44_list(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct libscols_table *table = scols_new_table();
	const struct gr_dnat44_list_resp *resp;
	struct gr_dnat44_list_req req = {0};
	void *resp_ptr = NULL;

	if (table == NULL)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	if (gr_api_client_send_recv(c, GR_DNAT44_LIST, sizeof(req), &req, &resp_ptr) < 0) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	resp = resp_ptr;

	scols_table_new_column(table, "INTERFACE", 0, 0);
	scols_table_new_column(table, "DESTINATION", 0, 0);
	scols_table_new_column(table, "REPLACE", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_rules; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct gr_dnat44_rule *rule = &resp->rules[i];
		struct gr_iface iface;

		if (iface_from_id(c, rule->iface_id, &iface) < 0)
			scols_line_sprintf(line, 0, "%u", rule->iface_id);
		else
			scols_line_sprintf(line, 0, "%s", iface.name);

		scols_line_sprintf(line, 1, IP4_F, &rule->match);
		scols_line_sprintf(line, 2, IP4_F, &rule->replace);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		IP_ADD_CTX(root),
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
		IP_DEL_CTX(root),
		"dnat44 interface IFACE destination DEST",
		dnat44_del,
		"Delete a DNAT44 rule.",
		with_help("Input interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Destination IPv4 address to match.", ec_node_re("DEST", IPV4_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP_SHOW_CTX(root),
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
