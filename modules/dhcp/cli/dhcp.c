// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_dhcp.h>
#include <gr_display.h>
#include <gr_net_types.h>

#include <ecoli.h>

static cmd_status_t dhcp_enable_cmd(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_dhcp_start_req req;

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_DHCP_START, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dhcp_disable_cmd(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_dhcp_stop_req req;

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_DHCP_STOP, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dhcp_show_cmd(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_dhcp_status *status;
	int ret;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "INTERFACE", GR_DISP_LEFT); // 0
	gr_table_column(table, "STATE", GR_DISP_LEFT); // 1
	gr_table_column(table, "ADDRESS", GR_DISP_LEFT); // 2
	gr_table_column(table, "SERVER", GR_DISP_LEFT); // 3
	gr_table_column(table, "LEASE", GR_DISP_RIGHT); // 4

	gr_api_client_stream_foreach (status, ret, c, GR_DHCP_LIST, 0, NULL) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, status->iface_id));
		gr_table_cell(table, 1, "%s", gr_dhcp_state_name(status->state));

		if (status->assigned_ip != 0) {
			gr_table_cell(table, 2, IP4_F, &status->assigned_ip);
		} else {
			gr_table_cell(table, 2, "-");
		}

		if (status->server_ip != 0) {
			gr_table_cell(table, 3, IP4_F, &status->server_ip);
		} else {
			gr_table_cell(table, 3, "-");
		}

		if (status->lease_time != 0)
			gr_table_cell(table, 4, "%us", status->lease_time);
		else
			gr_table_cell(table, 4, "-");

		if (gr_table_print_row(table) < 0)
			continue;
	}

	gr_table_free(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("dhcp", "DHCP client.")),
		"enable IFACE",
		dhcp_enable_cmd,
		"Enable DHCP on interface.",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("dhcp", "DHCP client.")),
		"disable IFACE",
		dhcp_disable_cmd,
		"Disable DHCP on interface.",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("dhcp", "DHCP client.")),
		"show",
		dhcp_show_cmd,
		"Show DHCP client status."
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "dhcp",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
