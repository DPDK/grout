// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

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
	struct gr_iface *iface = iface_from_name(c, arg_str(p, "IFACE"));
	struct gr_snat44_add_req req = {.exist_ok = true};

	if (iface == NULL)
		return CMD_ERROR;
	req.policy.iface_id = iface->id;
	free(iface);

	if (arg_ip4_net(p, "NET", &req.policy.net, true) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "REPLACE", &req.policy.replace) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SNAT44_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t snat44_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface *iface = iface_from_name(c, arg_str(p, "IFACE"));
	struct gr_snat44_del_req req = {.missing_ok = true};

	if (iface == NULL)
		return CMD_ERROR;
	req.policy.iface_id = iface->id;
	free(iface);

	if (arg_ip4_net(p, "NET", &req.policy.net, true) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "REPLACE", &req.policy.replace) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_SNAT44_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t snat44_list(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_snat44_policy *policy;
	struct libscols_table *table;
	int ret;

	table = scols_new_table();
	scols_table_new_column(table, "INTERFACE", 0, 0);
	scols_table_new_column(table, "SUBNET", 0, 0);
	scols_table_new_column(table, "REPLACE", 0, 0);
	scols_table_set_column_separator(table, "  ");

	gr_api_client_stream_foreach (policy, ret, c, GR_SNAT44_LIST, 0, NULL) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		struct gr_iface *iface = iface_from_id(c, policy->iface_id);

		if (iface == NULL)
			scols_line_sprintf(line, 0, "%u", policy->iface_id);
		else
			scols_line_sprintf(line, 0, "%s", iface->name);
		free(iface);

		scols_line_sprintf(line, 1, IP4_F "/%hhu", &policy->net.ip, policy->net.prefixlen);
		scols_line_sprintf(line, 2, IP4_F, &policy->replace);
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

#define SNAT_CTX(root) CLI_CONTEXT(root, CTX_ARG("snat44", "Dynamic source NAT44."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		SNAT_CTX(root),
		"add interface IFACE subnet NET replace REPLACE",
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
		SNAT_CTX(root),
		"del interface IFACE subnet NET replace REPLACE",
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
	ret = CLI_COMMAND(SNAT_CTX(root), "[show]", snat44_list, "Display SNAT44 policies.");
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "snat44",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
