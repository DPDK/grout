// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "cli.h"
#include "cli_event.h"
#include "cli_iface.h"
#include "display.h"

#include <gr_api.h>
#include <gr_l2.h>
#include <gr_net_types.h>

#include <ecoli.h>

static cmd_status_t vtep_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_flood_add_req req = {
		.entry.type = GR_FLOOD_T_VTEP,
		.exist_ok = true,
	};

	if (arg_ip4(p, "ADDR", &req.entry.vtep.addr) < 0)
		return CMD_ERROR;
	if (arg_u32(p, "VNI", &req.entry.vtep.vni) < 0)
		return CMD_ERROR;
	if (arg_vrf(c, p, "VRF", &req.entry.vrf_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_FLOOD_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t vtep_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_flood_del_req req = {
		.entry.type = GR_FLOOD_T_VTEP,
		.missing_ok = true,
	};

	if (arg_ip4(p, "ADDR", &req.entry.vtep.addr) < 0)
		return CMD_ERROR;
	if (arg_u32(p, "VNI", &req.entry.vtep.vni) < 0)
		return CMD_ERROR;
	if (arg_vrf(c, p, "VRF", &req.entry.vrf_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_FLOOD_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t vtep_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_flood_list_req req = {
		.type = GR_FLOOD_T_VTEP,
		.vrf_id = GR_VRF_ID_UNDEF,
	};
	const struct gr_flood_entry *entry;
	int ret;

	if (arg_str(p, "VRF") != NULL && arg_vrf(c, p, "VRF", &req.vrf_id) < 0)
		return CMD_ERROR;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "VNI", GR_DISP_RIGHT | GR_DISP_INT); // 0
	gr_table_column(table, "VRF", GR_DISP_LEFT); // 1
	gr_table_column(table, "ADDR", GR_DISP_LEFT); // 2

	gr_api_client_stream_foreach (entry, ret, c, GR_FLOOD_LIST, sizeof(req), &req) {
		gr_table_cell(table, 0, "%u", entry->vtep.vni);
		gr_table_cell(table, 1, "%s", iface_name_from_id(c, entry->vrf_id));
		gr_table_cell(table, 2, IP4_F, &entry->vtep.addr);

		if (gr_table_print_row(table) < 0)
			continue;
	}

	gr_table_free(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

#define FLOOD_CTX(root) CLI_CONTEXT(root, CTX_ARG("flood", "Flood list management."))
#define VTEP_CTX(root) CLI_CONTEXT(FLOOD_CTX(root), CTX_ARG("vtep", "VXLAN Tunnel End-Points."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		VTEP_CTX(root),
		"add ADDR vni VNI [vrf VRF]",
		vtep_add,
		"Add a VXLAN flood VTEP.",
		with_help("Remote VTEP IP address.", ec_node_re("ADDR", IPV4_RE)),
		with_help(
			"VXLAN Network Identifier (1-16777215).",
			ec_node_uint("VNI", 1, 16777215, 10)
		),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		VTEP_CTX(root),
		"del ADDR vni VNI [vrf VRF]",
		vtep_del,
		"Delete a VXLAN flood VTEP.",
		with_help("Remote VTEP IP address.", ec_node_re("ADDR", IPV4_RE)),
		with_help(
			"VXLAN Network Identifier (1-16777215).",
			ec_node_uint("VNI", 1, 16777215, 10)
		),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		VTEP_CTX(root),
		"[show] [vrf VRF]",
		vtep_show,
		"List VXLAN flood VTEPs.",
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "flood",
	.init = ctx_init,
};

static void flood_event_print(uint32_t event, const void *obj) {
	const struct gr_flood_entry *entry = obj;
	const char *action;

	switch (event) {
	case GR_EVENT_FLOOD_ADD:
		action = "add";
		break;
	case GR_EVENT_FLOOD_DEL:
		action = "del";
		break;
	default:
		action = "?";
		break;
	}

	printf("flood %s: %s vrf=%u", action, gr_flood_type_name(entry->type), entry->vrf_id);
	switch (entry->type) {
	case GR_FLOOD_T_VTEP:
		printf(" " IP4_F " vni=%u", &entry->vtep.addr, entry->vtep.vni);
	}
	printf("\n");
}

static struct cli_event_printer printer = {
	.name = "flood",
	.print = flood_event_print,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_FLOOD_ADD,
		GR_EVENT_FLOOD_DEL,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_event_printer_register(&printer);
}
