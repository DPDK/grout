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

static cmd_status_t snat44_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_snat44_add_req req = {.exist_ok = true};
	struct gr_iface iface;

	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;
	req.policy.iface_id = iface.id;
	if (arg_ip4_net(p, "NET", &req.policy.net, true) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "REPLACE", &req.policy.replace) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SNAT44_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t snat44_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_snat44_del_req req = {.missing_ok = true};
	struct gr_iface iface;

	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;
	req.policy.iface_id = iface.id;
	if (arg_ip4_net(p, "NET", &req.policy.net, true) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "REPLACE", &req.policy.replace) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SNAT44_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t snat44_list(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_snat44_list_resp *resp;
	struct libscols_table *table;
	cmd_status_t ret = CMD_ERROR;
	void *resp_ptr = NULL;

	table = scols_new_table();
	if (table == NULL)
		goto end;

	if (gr_api_client_send_recv(c, GR_SNAT44_LIST, 0, NULL, &resp_ptr) < 0)
		goto end;

	resp = resp_ptr;

	scols_table_new_column(table, "INTERFACE", 0, 0);
	scols_table_new_column(table, "SUBNET", 0, 0);
	scols_table_new_column(table, "REPLACE", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_policies; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct gr_snat44_policy *policy = &resp->policies[i];
		struct gr_iface iface;

		if (iface_from_id(c, policy->iface_id, &iface) < 0)
			scols_line_sprintf(line, 0, "%u", policy->iface_id);
		else
			scols_line_sprintf(line, 0, "%s", iface.name);

		scols_line_sprintf(line, 1, IP4_F "/%hhu", &policy->net.ip, policy->net.prefixlen);
		scols_line_sprintf(line, 2, IP4_F, &policy->replace);
	}

	scols_print_table(table);
	ret = CMD_SUCCESS;
end:
	if (table)
		scols_unref_table(table);
	free(resp_ptr);

	return ret;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		POLICY_ADD_CTX(root),
		"snat44 interface IFACE subnet NET replace REPLACE",
		snat44_add,
		"Create a SNAT44 policy.",
		with_help("Output interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help(
			"Source address subnet for which to perform source NAT.",
			ec_node_re("NET", IPV4_NET_RE)
		),
		with_help(
			"Replace source address with this IPv4 address.",
			ec_node_re("REPLACE", IPV4_RE)
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		POLICY_DEL_CTX(root),
		"snat44 interface IFACE subnet NET replace REPLACE",
		snat44_del,
		"Delete a SNAT44 policy.",
		with_help("Output interface.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help(
			"Source address subnet for which to perform source NAT.",
			ec_node_re("NET", IPV4_NET_RE)
		),
		with_help(
			"Replace source address with this IPv4 address.",
			ec_node_re("REPLACE", IPV4_RE)
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(POLICY_SHOW_CTX(root), "snat44", snat44_list, "Display SNAT44 policies.");
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "snat44",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
