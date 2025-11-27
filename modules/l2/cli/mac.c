// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "bridge.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_infra.h>
#include <gr_l2.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

// MAC table management commands
static cmd_status_t mac_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mac_add_req req;
	struct gr_l2_bridge *bridge;
	struct rte_ether_addr mac;
	const char *bridge_name;
	const char *iface_name;
	struct gr_iface *iface;
	int ret;

	bridge_name = arg_str(p, "BRIDGE");
	if (bridge_name == NULL) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	bridge = bridge_from_name(c, bridge_name);
	if (bridge == NULL) {
		errno = ENOENT;
		return CMD_ERROR;
	}

	if (arg_eth_addr(p, "MAC", &mac) < 0) {
		printf("Error: Invalid or missing MAC address\n");
		return CMD_ERROR;
	}

	iface_name = arg_str(p, "IFACE");
	if (iface_name == NULL) {
		printf("Error: Interface name required\n");
		return CMD_ERROR;
	}

	iface = iface_from_name(c, iface_name);
	if (iface == NULL)
		return CMD_ERROR;

	req.bridge_id = bridge->bridge_id;
	free(bridge);
	req.iface_id = iface->id;
	req.mac = mac;
	req.type = arg_str(p, "static") ? GR_L2_MAC_STATIC : GR_L2_MAC_DYNAMIC;

	ret = gr_api_client_send_recv(c, GR_L2_MAC_ADD, sizeof(req), &req, NULL);

	free(iface);

	if (ret < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t mac_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mac_del_req req;
	struct gr_l2_bridge *bridge;
	struct rte_ether_addr mac;
	const char *bridge_name;
	int ret;

	bridge_name = arg_str(p, "BRIDGE");
	if (bridge_name == NULL) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	bridge = bridge_from_name(c, bridge_name);
	if (bridge == NULL) {
		errno = ENOENT;
		return CMD_ERROR;
	}

	if (arg_eth_addr(p, "MAC", &mac) < 0) {
		printf("Error: Invalid or missing MAC address\n");
		return CMD_ERROR;
	}

	req.bridge_id = bridge->bridge_id;
	free(bridge);
	req.mac = mac;

	ret = gr_api_client_send_recv(c, GR_L2_MAC_DEL, sizeof(req), &req, NULL);
	if (ret < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t mac_list(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mac_list_req req = {0};
	const struct gr_l2_mac_entry *entry;
	struct libscols_table *table;
	struct gr_l2_bridge *bridge;
	const char *bridge_name;
	int ret;

	// Optional bridge ID filter
	bridge_name = arg_str(p, "BRIDGE");
	if (bridge_name) {
		bridge = bridge_from_name(c, bridge_name);
		if (bridge == NULL) {
			errno = ENOENT;
			return CMD_ERROR;
		}
		req.bridge_id = bridge->bridge_id;
		free(bridge);
	}

	table = scols_new_table();
	if (table == NULL)
		return CMD_ERROR;

	scols_table_new_column(table, "BRIDGE", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "MAC_ADDRESS", 0, 0);
	scols_table_new_column(table, "IFACE_ID", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "IFACE_NAME", 0, 0);
	scols_table_new_column(table, "TYPE", 0, 0);
	scols_table_new_column(table, "AGE", 0, SCOLS_FL_RIGHT);

	gr_api_client_stream_foreach (entry, ret, c, GR_L2_MAC_LIST, sizeof(req), &req) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		char mac_str[18]; // xx:xx:xx:xx:xx:xx format
		struct gr_iface *iface;

		snprintf(mac_str, sizeof(mac_str), ETH_F, &entry->mac);

		// Get interface name
		iface = iface_from_id(c, entry->iface_id);

		scols_line_sprintf(line, 0, "%u", entry->bridge_id);
		scols_line_set_data(line, 1, mac_str);
		scols_line_sprintf(line, 2, "%u", entry->iface_id);

		if (iface != NULL) {
			scols_line_set_data(line, 3, iface->name);
			free(iface);
		} else {
			scols_line_set_data(line, 3, "?");
		}

		scols_line_set_data(
			line, 4, entry->type == GR_L2_MAC_STATIC ? "static" : "dynamic"
		);

		if (entry->type == GR_L2_MAC_STATIC) {
			scols_line_set_data(line, 5, "-");
		} else {
			scols_line_sprintf(line, 5, "%u", entry->age);
		}
	}

	if (ret < 0) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	scols_print_table(table);
	scols_unref_table(table);
	return CMD_SUCCESS;
}

static cmd_status_t mac_flush(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_mac_flush_req req = {0};
	struct gr_iface *iface = NULL;
	struct gr_l2_bridge *bridge;
	const char *bridge_name;
	const char *iface_name;
	int ret;

	bridge_name = arg_str(p, "BRIDGE");
	if (bridge_name == NULL) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	bridge = bridge_from_name(c, bridge_name);
	if (bridge == NULL) {
		errno = ENOENT;
		return CMD_ERROR;
	}
	req.bridge_id = bridge->bridge_id;
	free(bridge);
	req.dynamic_only = arg_str(p, "dynamic_only") != NULL;

	// Optional interface filter
	iface_name = arg_str(p, "IFACE");
	if (iface_name != NULL) {
		iface = iface_from_name(c, iface_name);
		if (iface == NULL)
			return CMD_ERROR;
		req.iface_id = iface->id;
	}

	ret = gr_api_client_send_recv(c, GR_L2_MAC_FLUSH, sizeof(req), &req, NULL);

	if (iface != NULL)
		free(iface);

	if (ret < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

// CLI command registration
static int ctx_init(struct ec_node *root) {
	int ret;

	// MAC table commands
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("bridge", "Layer 2 bridge configuration.")),
		"mac add br BRIDGE mac MAC iface IFACE [static]",
		mac_add,
		"Add MAC address entry.",
		with_help("Bridge name.", ec_node_dyn("BRIDGE", complete_bridge_names, NULL)),
		with_help("MAC address (xx:xx:xx:xx:xx:xx).", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("Create static entry.", ec_node_str("static", "static"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("bridge", "Layer 2 bridge configuration.")),
		"mac del br BRIDGE mac MAC",
		mac_del,
		"Delete MAC address entry.",
		with_help("Bridge name.", ec_node_dyn("BRIDGE", complete_bridge_names, NULL)),
		with_help("MAC address (xx:xx:xx:xx:xx:xx).", ec_node_re("MAC", ETH_ADDR_RE))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("bridge", "Layer 2 bridge configuration.")),
		"mac list [BRIDGE]",
		mac_list,
		"List MAC address entries.",
		with_help("Bridge name.", ec_node_dyn("BRIDGE", complete_bridge_names, NULL))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("bridge", "Layer 2 bridge configuration.")),
		"mac flush br BRIDGE [iface IFACE] [dynamic_only]",
		mac_flush,
		"Flush MAC address entries.",
		with_help("Bridge name.", ec_node_dyn("BRIDGE", complete_bridge_names, NULL)),
		with_help(
			"Interface name (optional).",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help(
			"Flush only dynamic entries.", ec_node_str("dynamic_only", "dynamic_only")
		)
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "bridge",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
