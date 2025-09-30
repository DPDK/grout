// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_ip6.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

static cmd_status_t ra_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface *iface = iface_from_name(c, arg_str(p, "IFACE"));
	const struct gr_ip6_ra_conf *ra;
	struct gr_ip6_ra_show_req req;
	int ret;

	if (iface != NULL)
		req.iface_id = iface->id;
	else
		req.iface_id = GR_IFACE_ID_UNDEF;
	free(iface);

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "RA", 0, 0);
	scols_table_new_column(table, "INTERVAL", 0, 0);
	scols_table_new_column(table, "LIFETIME", 0, 0);
	scols_table_set_column_separator(table, "  ");

	gr_api_client_stream_foreach (ra, ret, c, GR_IP6_IFACE_RA_SHOW, sizeof(req), &req) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		iface = iface_from_id(c, ra->iface_id);
		if (iface != NULL)
			scols_line_sprintf(line, 0, "%s", iface->name);
		else
			scols_line_sprintf(line, 0, "%u", ra->iface_id);
		free(iface);
		scols_line_sprintf(line, 1, "%u", ra->enabled);
		scols_line_sprintf(line, 2, "%u", ra->interval);
		scols_line_sprintf(line, 3, "%u", ra->lifetime);
	}

	scols_print_table(table);
	scols_unref_table(table);
	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t ra_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface *iface = iface_from_name(c, arg_str(p, "IFACE"));
	struct gr_ip6_ra_set_req req = {0};

	if (iface == NULL)
		return CMD_ERROR;

	req.iface_id = iface->id;
	free(iface);

	if (!arg_u16(p, "IT", &req.interval))
		req.set_interval = 1;

	if (!arg_u16(p, "LT", &req.lifetime))
		req.set_lifetime = 1;

	if (gr_api_client_send_recv(c, GR_IP6_IFACE_RA_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;
	return CMD_SUCCESS;
}

static cmd_status_t ra_clear(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface *iface = iface_from_name(c, arg_str(p, "IFACE"));
	struct gr_ip6_ra_clear_req req;

	if (iface == NULL)
		return CMD_ERROR;

	req.iface_id = iface->id;
	free(iface);

	if (gr_api_client_send_recv(c, GR_IP6_IFACE_RA_CLEAR, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;
	return CMD_SUCCESS;
}

#define RA_CTX(root) CLI_CONTEXT(root, CTX_ARG("router-advert", "IPv6 router advertisements."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		RA_CTX(root),
		"set IFACE [interval IT] [lifetime LT]",
		ra_set,
		"Set router advertisement parameters",
		with_help("Interface name.", ec_node_dyn("IFACE", complete_iface_names, NULL)),
		with_help("Interval", ec_node_uint("IT", 0, UINT16_MAX - 1, 10)),
		with_help("Life time", ec_node_uint("LT", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		RA_CTX(root),
		"clear IFACE",
		ra_clear,
		"Disable router advertisement and reset parameters",
		with_help("Interface name.", ec_node_dyn("IFACE", complete_iface_names, NULL))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		RA_CTX(root),
		"[show] [interface IFACE]",
		ra_show,
		"Show router advertisement configuration",
		with_help("Interface name.", ec_node_dyn("IFACE", complete_iface_names, NULL))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "ipv6 router-advert",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
