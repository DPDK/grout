// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "ip.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_ip6.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

static cmd_status_t ra_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_ra_show_resp *resp;
	struct gr_ip6_ra_show_req req;
	struct gr_iface iface;
	void *resp_ptr = NULL;

	if (!iface_from_name(c, arg_str(p, "IFACE"), &iface))
		req.iface_id = iface.id;
	else
		req.iface_id = 0;

	if (gr_api_client_send_recv(c, GR_IP6_IFACE_RA_SHOW, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;
	resp = resp_ptr;

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "RA", 0, 0);
	scols_table_new_column(table, "interval", 0, 0);
	scols_table_new_column(table, "lifetime", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (uint16_t i = 0; i < resp->n_ras; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		if (iface_from_id(c, resp->ras[i].iface_id, &iface) == 0)
			scols_line_sprintf(line, 0, "%s", iface.name);
		else
			scols_line_sprintf(line, 0, "%u", resp->ras[i].iface_id);
		scols_line_sprintf(line, 1, "%u", resp->ras[i].enabled);
		scols_line_sprintf(line, 2, "%u", resp->ras[i].interval);
		scols_line_sprintf(line, 3, "%u", resp->ras[i].lifetime);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t ra_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_ra_set_req req = {0};
	struct gr_iface iface;

	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;

	req.iface_id = iface.id;
	if (!arg_u16(p, "IT", &req.interval))
		req.set_interval = 1;

	if (!arg_u16(p, "LT", &req.lifetime))
		req.set_lifetime = 1;

	if (gr_api_client_send_recv(c, GR_IP6_IFACE_RA_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;
	return CMD_SUCCESS;
}

static cmd_status_t ra_clear(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_ra_clear_req req;
	struct gr_iface iface;

	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;

	req.iface_id = iface.id;
	if (gr_api_client_send_recv(c, GR_IP6_IFACE_RA_CLEAR, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;
	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		IP6_SHOW_CTX(root),
		"router-advert [IFACE]",
		ra_show,
		"Show router advertisement configuration",
		with_help("Interface name.", ec_node_dyn("IFACE", complete_iface_names, NULL))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		IP6_SET_CTX(root),
		"router-advert IFACE [interval IT] [lifetime LT]",
		ra_set,
		"Set router advertisement parameters",
		with_help("Interface name.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Interval", ec_node_uint("IT", 0, UINT16_MAX - 1, 10)),
		with_help("Life time", ec_node_uint("LT", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		IP6_CLEAR_CTX(root),
		"router-advert IFACE",
		ra_clear,
		"Disable router advertisement and reset parameters",
		with_help("Interface name.", ec_node_dyn("IFACE", complete_iface_names, NULL))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "ipv6 router-advert",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
