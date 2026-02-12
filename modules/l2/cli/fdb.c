// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_event.h>
#include <gr_cli_iface.h>
#include <gr_clock.h>
#include <gr_l2.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>

static int bridge_from_name(struct gr_api_client *c, const char *name, uint16_t *bridge_id) {
	struct gr_iface *iface = iface_from_name(c, name);
	if (iface == NULL)
		return -errno;

	if (iface->type != GR_IFACE_TYPE_BRIDGE) {
		free(iface);
		return errno_set(EMEDIUMTYPE);
	}

	*bridge_id = iface->id;
	free(iface);
	return 0;
}

static cmd_status_t fdb_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_fdb_add_req req = {.exist_ok = true};
	struct gr_iface *iface;

	if (arg_eth_addr(p, "MAC", &req.fdb.mac) < 0)
		return CMD_ERROR;

	iface = iface_from_name(c, arg_str(p, "IFACE"));
	if (iface == NULL)
		return CMD_ERROR;
	req.fdb.iface_id = iface->id;
	free(iface);

	if (arg_u16(p, "VLAN", &req.fdb.vlan_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	req.fdb.flags = GR_FDB_F_STATIC;

	if (gr_api_client_send_recv(c, GR_FDB_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t fdb_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_fdb_del_req req = {.missing_ok = true};

	if (bridge_from_name(c, arg_str(p, "BRIDGE"), &req.key.bridge_id) < 0)
		return CMD_ERROR;
	if (arg_eth_addr(p, "MAC", &req.key.mac) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "VLAN", &req.key.vlan_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_FDB_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t fdb_flush(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_fdb_flush_req req = {
		.bridge_id = GR_IFACE_ID_UNDEF,
		.iface_id = GR_IFACE_ID_UNDEF,
		.flags = 0,
	};
	struct gr_iface *iface;

	if (arg_str(p, "BRIDGE") != NULL) {
		if (bridge_from_name(c, arg_str(p, "BRIDGE"), &req.bridge_id) < 0)
			return CMD_ERROR;
	}

	if (arg_str(p, "IFACE") != NULL) {
		iface = iface_from_name(c, arg_str(p, "IFACE"));
		if (iface == NULL)
			return CMD_ERROR;
		req.iface_id = iface->id;
		free(iface);
	}

	if (arg_eth_addr(p, "MAC", &req.mac) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (arg_str(p, "all") != NULL)
		req.flags = GR_FDB_F_STATIC;

	if (gr_api_client_send_recv(c, GR_FDB_FLUSH, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t fdb_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_fdb_list_req req = {.bridge_id = GR_IFACE_ID_UNDEF};
	const struct gr_fdb_entry *fdb;
	int ret;

	if (arg_str(p, "BRIDGE") != NULL) {
		if (bridge_from_name(c, arg_str(p, "BRIDGE"), &req.bridge_id) < 0)
			return CMD_ERROR;
	}

	if (arg_str(p, "static") != NULL)
		req.flags = GR_FDB_F_STATIC;

	struct libscols_table *table = scols_new_table();
	scols_table_new_column(table, "BRIDGE", 0, 0);
	scols_table_new_column(table, "MAC", 0, 0);
	scols_table_new_column(table, "VLAN", 0, 0);
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "AGE", 0, SCOLS_FL_RIGHT);
	scols_table_set_column_separator(table, "  ");

	gr_api_client_stream_foreach (fdb, ret, c, GR_FDB_LIST, sizeof(req), &req) {
		struct libscols_line *line = scols_table_new_line(table, NULL);

		struct gr_iface *bridge = iface_from_id(c, fdb->bridge_id);
		scols_line_sprintf(line, 0, "%s", bridge ? bridge->name : "[deleted]");
		free(bridge);

		scols_line_sprintf(line, 1, ETH_F, &fdb->mac);

		if (fdb->vlan_id != 0)
			scols_line_sprintf(line, 2, "%u", fdb->vlan_id);

		struct gr_iface *iface = iface_from_id(c, fdb->iface_id);
		scols_line_sprintf(line, 3, "%s", iface ? iface->name : "[deleted]");
		free(iface);

		if (fdb->flags & GR_FDB_F_STATIC) {
			scols_line_set_data(line, 4, "static");
		} else {
			scols_line_sprintf(
				line, 4, "%lds", (gr_clock_us() - fdb->last_seen) / CLOCKS_PER_SEC
			);
		}
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t fdb_config_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_fdb_config_set_req req;

	if (arg_u32(p, "MAX", &req.max_entries) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_FDB_CONFIG_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t fdb_config_show(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_fdb_config_get_resp *resp;
	void *resp_ptr = NULL;
	float used = 0.0;

	if (gr_api_client_send_recv(c, GR_FDB_CONFIG_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	if (resp->max_entries != 0)
		used = (100.0 * (float)resp->used_entries) / (float)resp->max_entries;
	printf("used %u (%.01f%%)\n", resp->used_entries, used);
	printf("max %u\n", resp->max_entries);
	free(resp_ptr);

	return CMD_SUCCESS;
}

#define FDB_CTX(root) CLI_CONTEXT(root, CTX_ARG("fdb", "Forwarding database."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		FDB_CTX(root),
		"add MAC iface IFACE [vlan VLAN]",
		fdb_add,
		"Add a static FDB entry.",
		with_help("MAC address.", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help(
			"Bridge member interface.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("VLAN ID.", ec_node_uint("VLAN", 1, 4094, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		FDB_CTX(root),
		"del bridge BRIDGE MAC [vlan VLAN]",
		fdb_del,
		"Delete an FDB entry.",
		with_help(
			"Bridge interface.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("MAC address.", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help("VLAN ID.", ec_node_uint("VLAN", 1, 4094, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		FDB_CTX(root),
		"flush [(bridge BRIDGE),(iface IFACE),(mac MAC),(all)]",
		fdb_flush,
		"Flush dynamic FDB entries.",
		with_help(
			"Flush only entries on this bridge.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help(
			"Flush only entries on this interface.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help(
			"Flush only entries matching this MAC address.",
			ec_node_re("MAC", ETH_ADDR_RE)
		),
		with_help("Flush all entries including static.", ec_node_str("all", "all"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		FDB_CTX(root),
		"config set max MAX",
		fdb_config_set,
		"Change the FDB configuration.",
		with_help("Maximum number of FDB entries.", ec_node_uint("MAX", 1, UINT32_MAX, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		FDB_CTX(root),
		"config [show]",
		fdb_config_show,
		"Show the current FDB configuration."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		FDB_CTX(root),
		"[show] [(bridge BRIDGE),(static)]",
		fdb_show,
		"Show FDB entries.",
		with_help(
			"Show only entries on this bridge.",
			ec_node_dyn("BRIDGE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_BRIDGE))
		),
		with_help("Show only static entries.", ec_node_str("static", "static"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "fdb",
	.init = ctx_init,
};

static void fdb_event_print(uint32_t event, const void *obj) {
	const struct gr_fdb_entry *fdb = obj;
	const char *action;

	switch (event) {
	case GR_EVENT_FDB_ADD:
		action = "add";
		break;
	case GR_EVENT_FDB_DEL:
		action = "del";
		break;
	case GR_EVENT_FDB_UPDATE:
		action = "update";
		break;
	default:
		action = "?";
		break;
	}

	printf("fdb %s: bridge=%u " ETH_F, action, fdb->bridge_id, &fdb->mac);
	if (fdb->vlan_id != 0)
		printf(" vlan=%u", fdb->vlan_id);
	printf(" iface=%u", fdb->iface_id);
	printf(" %s\n", (fdb->flags & GR_FDB_F_STATIC) ? "static" : "dynamic");
}

static struct cli_event_printer printer = {
	.print = fdb_event_print,
	.ev_count = 3,
	.ev_types = {
		GR_EVENT_FDB_ADD,
		GR_EVENT_FDB_DEL,
		GR_EVENT_FDB_UPDATE,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_event_printer_register(&printer);
}
