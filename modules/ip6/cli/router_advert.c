// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_display.h>
#include <gr_ip6.h>
#include <gr_net_types.h>

#include <ecoli.h>

static cmd_status_t ra_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_ra_show_req req = {.iface_id = GR_IFACE_ID_UNDEF};
	const struct gr_ip6_ra_conf *ra;
	int ret;

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "IFACE", GR_DISP_LEFT); // 0
	gr_table_column(table, "RA", GR_DISP_BOOL); // 1
	gr_table_column(table, "INTERVAL", GR_DISP_RIGHT | GR_DISP_INT); // 2
	gr_table_column(table, "LIFETIME", GR_DISP_RIGHT | GR_DISP_INT); // 3

	gr_api_client_stream_foreach (ra, ret, c, GR_IP6_IFACE_RA_SHOW, sizeof(req), &req) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, ra->iface_id));
		gr_table_cell(table, 1, "%u", ra->enabled);
		gr_table_cell(table, 2, "%u", ra->interval);
		gr_table_cell(table, 3, "%u", ra->lifetime);

		if (gr_table_print_row(table) < 0)
			break;
	}

	gr_table_free(table);
	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t ra_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_ra_set_req req = {0};

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0)
		return CMD_ERROR;
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

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0)
		return CMD_ERROR;

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
