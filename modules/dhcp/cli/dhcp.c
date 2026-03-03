// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_dhcp.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

static cmd_status_t dhcp_enable_cmd(struct gr_api_client *c, const struct ec_pnode *p) {
	const char *iface_name = arg_str(p, "IFACE");
	struct gr_dhcp_start_req req;
	struct gr_iface *iface;

	iface = iface_from_name(c, iface_name);
	if (iface == NULL)
		return CMD_ERROR;

	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_DHCP_START, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dhcp_disable_cmd(struct gr_api_client *c, const struct ec_pnode *p) {
	const char *iface_name = arg_str(p, "IFACE");
	struct gr_dhcp_stop_req req;
	struct gr_iface *iface;

	iface = iface_from_name(c, iface_name);
	if (iface == NULL)
		return CMD_ERROR;

	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_DHCP_STOP, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t dhcp_show_cmd(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_dhcp_status *status;
	struct libscols_table *table;
	int ret;

	table = scols_new_table();
	if (table == NULL)
		return CMD_ERROR;

	scols_table_new_column(table, "INTERFACE", 0, 0);
	scols_table_new_column(table, "STATE", 0, 0);
	scols_table_new_column(table, "ADDRESS", 0, 0);
	scols_table_new_column(table, "SERVER", 0, 0);
	scols_table_new_column(table, "LEASE", 0, SCOLS_FL_RIGHT);

	if (arg_str(p, "json")) {
		scols_table_enable_json(table, 1);
		scols_table_set_name(table, "dhcp");
		scols_column_set_json_type(scols_table_get_column(table, 4), SCOLS_JSON_NUMBER);
	}

	gr_api_client_stream_foreach (status, ret, c, GR_DHCP_LIST, 0, NULL) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		struct gr_iface *iface = iface_from_id(c, status->iface_id);

		if (iface != NULL) {
			scols_line_sprintf(line, 0, "%s", iface->name);
			free(iface);
		} else {
			scols_line_sprintf(line, 0, "%u", status->iface_id);
		}

		scols_line_sprintf(line, 1, "%s", gr_dhcp_state_name(status->state));

		if (status->assigned_ip != 0) {
			scols_line_sprintf(line, 2, IP4_F, &status->assigned_ip);
		} else {
			scols_line_sprintf(line, 2, "-");
		}

		if (status->server_ip != 0) {
			scols_line_sprintf(line, 3, IP4_F, &status->server_ip);
		} else {
			scols_line_sprintf(line, 3, "-");
		}

		scols_line_sprintf(line, 4, "%u", status->lease_time);
	}

	if (ret < 0) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	scols_print_table(table);
	scols_unref_table(table);

	return CMD_SUCCESS;
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
		"show [json]",
		dhcp_show_cmd,
		"Show DHCP client status.",
		with_help("Output in JSON format.", ec_node_str("json", "json"))
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
