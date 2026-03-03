// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_display.h>
#include <gr_nat.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <stdint.h>

static cmd_status_t snat44_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_snat44_add_req req = {.exist_ok = true};

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.policy.iface_id) < 0)
		return CMD_ERROR;
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

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.policy.iface_id) < 0)
		return CMD_ERROR;
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
	int ret;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "INTERFACE", GR_DISP_LEFT); // 0
	gr_table_column(table, "SUBNET", GR_DISP_LEFT); // 1
	gr_table_column(table, "REPLACE", GR_DISP_LEFT); // 2

	gr_api_client_stream_foreach (policy, ret, c, GR_SNAT44_LIST, 0, NULL) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, policy->iface_id));
		gr_table_cell(table, 1, IP4_NET_F, &policy->net);
		gr_table_cell(table, 2, IP4_F, &policy->replace);

		if (gr_table_print_row(table) < 0)
			break;
	}

	gr_table_free(table);

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
