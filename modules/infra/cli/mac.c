// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 David Marchand

#include "cli.h"
#include "cli_iface.h"
#include "display.h"

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>

static cmd_status_t mac_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_mac_add_req req = {0};

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0)
		return CMD_ERROR;

	if (arg_eth_addr(p, "MAC", &req.mac) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IFACE_MAC_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t mac_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_mac_del_req req = {0};

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0)
		return CMD_ERROR;

	if (arg_eth_addr(p, "MAC", &req.mac) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IFACE_MAC_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t mac_list(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_mac_list_req req = {.iface_id = GR_IFACE_ID_UNDEF};
	const struct gr_iface_mac *mac;
	int ret;

	if (arg_str(p, "IFACE") != NULL) {
		if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0)
			return CMD_ERROR;
	}

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "IFACE", GR_DISP_LEFT);
	gr_table_column(table, "MAC", GR_DISP_LEFT);
	gr_table_column(table, "REFCNT", GR_DISP_RIGHT | GR_DISP_INT);

	gr_api_client_stream_foreach (mac, ret, c, GR_IFACE_MAC_LIST, sizeof(req), &req) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, mac->iface_id));
		gr_table_cell(table, 1, ETH_F, &mac->mac);
		if (mac->primary)
			gr_table_cell(table, 2, "-");
		else
			gr_table_cell(table, 2, "%u", mac->refcnt);
		if (gr_table_print_row(table) < 0)
			break;
	}

	gr_table_free(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t mac_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_iface_mac_set_req req = {0};

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.iface_id) < 0)
		return CMD_ERROR;

	if (arg_eth_addr(p, "MAC", &req.mac) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IFACE_MAC_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define MAC_CTX(root) CLI_CONTEXT(root, CTX_ARG("mac", "MAC address management."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		MAC_CTX(root),
		"add MAC iface IFACE",
		mac_add,
		"Add a secondary MAC address to an interface.",
		with_help("MAC address.", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		MAC_CTX(root),
		"del MAC iface IFACE",
		mac_del,
		"Remove a secondary MAC address from an interface.",
		with_help("MAC address.", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		MAC_CTX(root),
		"set MAC iface IFACE",
		mac_set,
		"Set the primary MAC address of an interface.",
		with_help("MAC address.", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		MAC_CTX(root),
		"[show] [iface IFACE]",
		mac_list,
		"Display MAC addresses.",
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "mac",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
