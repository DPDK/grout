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

// Bridge interface type CLI support
static void bridge_show(struct gr_api_client *, const struct gr_iface *iface) {
	const struct gr_iface_info_bridge *bridge_info = PAYLOAD(iface);

	printf("bridge_id: %u mac: " ETH_F "\n", bridge_info->bridge_id, &bridge_info->base.mac);
}

static void
bridge_list_info(struct gr_api_client *, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_bridge *bridge_info = PAYLOAD(iface);

	snprintf(
		buf,
		len,
		"bridge_id: %u mac: " ETH_F,
		bridge_info->bridge_id,
		&bridge_info->base.mac
	);
}

static struct cli_iface_type bridge_iface_type = {
	.type_id = GR_IFACE_TYPE_BRIDGE,
	.show = bridge_show,
	.list_info = bridge_list_info,
};

// Bridge interface creation command
static cmd_status_t bridge_iface_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_add_req *req = NULL;
	struct gr_l2_bridge *bridge;
	const char *bridge_name;
	void *resp_ptr = NULL;
	size_t len;
	int ret;

	len = sizeof(*req) + sizeof(struct gr_iface_info_bridge);
	if ((req = calloc(1, len)) == NULL) {
		errno = ENOMEM;
		ret = -1;
		goto cleanup;
	}

	req->iface.type = GR_IFACE_TYPE_BRIDGE;
	req->iface.flags = GR_IFACE_F_UP;
	req->iface.mode = GR_IFACE_MODE_L3; // Bridge interfaces are L3 for IP processing
	req->iface.mtu = 1500;

	const char *name = arg_str(p, "NAME");
	if (name == NULL) {
		errno = EINVAL;
		ret = -1;
		goto cleanup;
	}
	strncpy(req->iface.name, name, sizeof(req->iface.name) - 1);

	bridge_name = arg_str(p, "BRIDGE");
	if (bridge_name == NULL) {
		errno = EINVAL;
		ret = -1;
		goto cleanup;
	}
	bridge = bridge_from_name(c, bridge_name);
	if (bridge == NULL) {
		errno = ENOENT;
		ret = -1;
		goto cleanup;
	}

	req->iface.domain_id = bridge->bridge_id;

	struct gr_iface_info_bridge *bridge_info = (struct gr_iface_info_bridge *)req->iface.info;
	bridge_info->bridge_id = bridge->bridge_id;
	free(bridge);

	ret = gr_api_client_send_recv(c, GR_INFRA_IFACE_ADD, len, req, &resp_ptr);

cleanup:
	free(resp_ptr);
	free(req);
	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

// Bridge domain management commands
static cmd_status_t bridge_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_bridge_add_req req = {0};
	uint32_t aging_time, max_mac_count;
	struct gr_l2_bridge *br;
	const char *name;
	void *resp_ptr;
	int ret;

	name = arg_str(p, "NAME");
	if (name == NULL) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	strncpy(req.name, name, sizeof(req.name) - 1);

	// Set default configuration
	req.config.aging_time = 300;
	req.config.max_mac_count = 1024;
	req.config.flood_unknown = true;

	// Parse optional parameters
	if (arg_u32(p, "AGING_TIME", &aging_time) == 0)
		req.config.aging_time = aging_time;

	if (arg_u32(p, "MAX_MAC_COUNT", &max_mac_count) == 0)
		req.config.max_mac_count = max_mac_count;

	if (arg_str(p, "no_flood"))
		req.config.flood_unknown = false;

	ret = gr_api_client_send_recv(c, GR_L2_BRIDGE_ADD, sizeof(req), &req, &resp_ptr);
	if (ret < 0)
		return CMD_ERROR;
	br = resp_ptr;
	printf("bridge %s created with id %u.\n", br->name, br->bridge_id);
	free(br);
	return CMD_SUCCESS;
}

static cmd_status_t bridge_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_bridge_del_req req;
	struct gr_l2_bridge *bridge;
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

	req.bridge_id = bridge->bridge_id;
	free(bridge);

	ret = gr_api_client_send_recv(c, GR_L2_BRIDGE_DEL, sizeof(req), &req, NULL);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t bridge_show_cmd(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_l2_bridge_member *member;
	struct gr_l2_bridge_get_req req;
	struct libscols_table *table;
	struct gr_l2_bridge *bridge;
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

	printf("Bridge Domain %u:\n", bridge->bridge_id);
	printf("  Name: %s\n", bridge->name);
	printf("  Bridge Interface ID: %u\n", bridge->iface_id);
	printf("  MAC Aging Time: %u seconds\n", bridge->config.aging_time);
	printf("  Max MAC Count: %u\n", bridge->config.max_mac_count);
	printf("  Flood Unknown: %s\n", bridge->config.flood_unknown ? "yes" : "no");
	printf("  Current MAC Count: %u\n", bridge->mac_count);
	printf("  Member Count: %u\n", bridge->member_count);

	table = scols_new_table();
	if (table == NULL) {
		ret = -1;
		errno = ENOMEM;
		goto cleanup;
	}

	scols_table_new_column(table, "BRIDGE_ID", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "IFACE_ID", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "IFACE_NAME", 0, 0);

	req.bridge_id = bridge->bridge_id;
	gr_api_client_stream_foreach (member, ret, c, GR_L2_BRIDGE_MEMBER_LIST, sizeof(req), &req) {
		struct libscols_line *line = scols_table_new_line(table, NULL);

		scols_line_sprintf(line, 0, "%u", member->bridge_id);
		scols_line_sprintf(line, 1, "%u", member->iface_id);
		scols_line_set_data(line, 2, member->iface_name);
	}

	scols_print_table(table);
	scols_unref_table(table);
cleanup:
	free(bridge);
	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t bridge_list(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_l2_bridge *bridge;
	struct libscols_table *table;
	int ret;

	table = scols_new_table();
	if (table == NULL)
		return CMD_ERROR;

	scols_table_new_column(table, "ID", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "NAME", 0, 0);
	scols_table_new_column(table, "IFACE", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "AGING", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "MAC_COUNT", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "MEMBERS", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "FLOOD", 0, 0);

	gr_api_client_stream_foreach (bridge, ret, c, GR_L2_BRIDGE_LIST, 0, NULL) {
		struct libscols_line *line = scols_table_new_line(table, NULL);

		scols_line_sprintf(line, 0, "%u", bridge->bridge_id);
		scols_line_set_data(line, 1, bridge->name);
		scols_line_sprintf(line, 2, "%u", bridge->iface_id);
		scols_line_sprintf(line, 3, "%u", bridge->config.aging_time);
		scols_line_sprintf(line, 4, "%u", bridge->mac_count);
		scols_line_sprintf(line, 5, "%u", bridge->member_count);
		scols_line_set_data(line, 6, bridge->config.flood_unknown ? "yes" : "no");
	}

	if (ret < 0) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	scols_print_table(table);
	scols_unref_table(table);
	return CMD_SUCCESS;
}

// Bridge member management
static cmd_status_t bridge_member_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_bridge_member_add_req req;
	const char *iface_name, *bridge_name;
	struct gr_l2_bridge *bridge = NULL;
	struct gr_iface *iface = NULL;
	int ret = -1;

	bridge_name = arg_str(p, "BRIDGE");
	if (bridge_name == NULL) {
		errno = EINVAL;
		goto cleanup;
	}
	bridge = bridge_from_name(c, bridge_name);
	if (bridge == NULL) {
		errno = ENOENT;
		goto cleanup;
	}

	iface_name = arg_str(p, "IFACE");
	if (iface_name == NULL) {
		errno = EINVAL;
		goto cleanup;
	}

	iface = iface_from_name(c, iface_name);
	if (iface == NULL) {
		errno = ENODEV;
		goto cleanup;
	}

	req.bridge_id = bridge->bridge_id;
	req.iface_id = iface->id;

	ret = gr_api_client_send_recv(c, GR_L2_BRIDGE_MEMBER_ADD, sizeof(req), &req, NULL);

cleanup:
	free(bridge);
	free(iface);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t bridge_member_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_l2_bridge_member_del_req req;
	struct gr_iface *iface = NULL;
	const char *iface_name;
	int ret;

	iface_name = arg_str(p, "IFACE");
	if (iface_name == NULL) {
		errno = EINVAL;
		ret = -1;
		goto cleanup;
	}

	iface = iface_from_name(c, iface_name);
	if (iface == NULL) {
		errno = ENODEV;
		ret = -1;
		goto cleanup;
	}

	if (iface->mode != GR_IFACE_MODE_L2_BRIDGE) {
		errno = EINVAL;
		ret = -1;
		goto cleanup;
	}

	req.bridge_id = iface->domain_id;
	req.iface_id = iface->id;

	ret = gr_api_client_send_recv(c, GR_L2_BRIDGE_MEMBER_DEL, sizeof(req), &req, NULL);

cleanup:
	free(iface);
	if (ret < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

struct gr_l2_bridge *bridge_from_name(struct gr_api_client *c, const char *name) {
	struct gr_l2_bridge_get_req req = {.bridge_id = GR_BRIDGE_ID_UNDEF};
	void *bridge;

	if (name == NULL)
		return errno_set_null(EINVAL);

	memccpy(req.name, name, 0, sizeof(req.name));

	if (gr_api_client_send_recv(c, GR_L2_BRIDGE_GET, sizeof(req), &req, &bridge) < 0)
		return NULL;
	return bridge;
}

int complete_bridge_names(
	struct gr_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void * /*cb_arg*/
) {
	const struct gr_l2_bridge *bridge;
	int result = 0;
	int ret;

	gr_api_client_stream_foreach (bridge, ret, c, GR_L2_BRIDGE_LIST, 0, NULL) {
		if (ec_str_startswith(bridge->name, arg)) {
			if (!ec_comp_add_item(comp, node, EC_COMP_FULL, arg, bridge->name))
				result = -1;
		}
	}

	return ret < 0 ? -1 : result;
}

// CLI command registration
static int ctx_init(struct ec_node *root) {
	int ret;

	// Bridge interface creation command
	ret = CLI_COMMAND(
		INTERFACE_ADD_CTX(root),
		"bridge NAME bridge BRIDGE",
		bridge_iface_add,
		"Create a new bridge interface.",
		with_help("Interface name.", ec_node("any", "NAME")),
		with_help("Bridge name.", ec_node_dyn("BRIDGE", complete_bridge_names, NULL))
	);
	if (ret < 0)
		return ret;

	// Bridge domain commands
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("bridge", "Layer 2 bridge configuration.")),
		"add NAME [(aging_time AGING_TIME),(max_mac_count MAX_MAC_COUNT),(no_flood)]",
		bridge_add,
		"Create a new bridge domain.",
		with_help("Bridge domain name.", ec_node("any", "NAME")),
		with_help(
			"MAC aging time in seconds (default: 300).",
			ec_node_uint("AGING_TIME", 0, UINT32_MAX, 10)
		),
		with_help(
			"Maximum MAC entries (default: 1024).",
			ec_node_uint("MAX_MAC_COUNT", 1, UINT32_MAX, 10)
		),
		with_help(
			"Disable flooding of unknown unicast.", ec_node_str("no_flood", "no_flood")
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("bridge", "Layer 2 bridge configuration.")),
		"del BRIDGE",
		bridge_del,
		"Delete a bridge domain.",
		with_help("Bridge name.", ec_node_dyn("BRIDGE", complete_bridge_names, NULL))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("bridge", "Layer 2 bridge configuration.")),
		"show BRIDGE",
		bridge_show_cmd,
		"Show bridge domain details.",
		with_help("Bridge name.", ec_node_dyn("BRIDGE", complete_bridge_names, NULL))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("bridge", "Layer 2 bridge configuration.")),
		"[list]",
		bridge_list,
		"List all bridge domains."
	);
	if (ret < 0)
		return ret;

	// Bridge member commands
	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"IFACE mode bridge BRIDGE",
		bridge_member_add,
		"Add interface to bridge domain.",
		with_help("Bridge name.", ec_node_dyn("BRIDGE", complete_bridge_names, NULL)),
		with_help(
			"Interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		INTERFACE_SET_CTX(root),
		"IFACE mode l3",
		bridge_member_del,
		"Remove interface from bridge domain.",
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
	.name = "bridge",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	register_iface_type(&bridge_iface_type);
}
