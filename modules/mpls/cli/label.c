// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "cli.h"
#include "cli_event.h"
#include "cli_iface.h"
#include "display.h"

#include <gr_api.h>
#include <gr_mpls.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>

static cmd_status_t mpls_route_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_mpls_label_route_add_req req = {
		.exist_ok = true,
		.origin = GR_NH_ORIGIN_STATIC,
	};

	if (arg_u32(p, "LABEL", &req.in_label) < 0)
		return CMD_ERROR;
	if (arg_u32(p, "ID", &req.nh_id) < 0)
		return CMD_ERROR;
	if (arg_vrf(c, p, "VRF", &req.vrf_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_MPLS_LABEL_ROUTE_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t mpls_route_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_mpls_label_route_del_req req = {.missing_ok = true};

	if (arg_u32(p, "LABEL", &req.in_label) < 0)
		return CMD_ERROR;
	if (arg_vrf(c, p, "VRF", &req.vrf_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_MPLS_LABEL_ROUTE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t mpls_route_get(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_mpls_label_route *resp;
	struct gr_mpls_label_route_get_req req = {0};
	void *resp_ptr = NULL;

	if (arg_u32(p, "LABEL", &req.in_label) < 0)
		return CMD_ERROR;
	if (arg_vrf(c, p, "VRF", &req.vrf_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_MPLS_LABEL_ROUTE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	struct gr_object *o = gr_object_new(NULL);
	gr_object_field(o, "vrf", 0, "%s", iface_name_from_id(c, resp->vrf_id));
	gr_object_field(o, "label", 0, "%u", resp->in_label);
	gr_object_field(o, "nexthop_id", 0, "%u", resp->nh_id);
	gr_object_field(o, "origin", 0, "%s", gr_nh_origin_name(resp->origin));
	gr_object_free(o);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t mpls_route_list(struct gr_api_client *c, const struct ec_pnode *p) {
	uint16_t vrf_id = GR_VRF_ID_UNDEF;
	uint16_t max_routes = 1000;
	const struct gr_mpls_label_route *route;
	int ret;

	if (arg_str(p, "VRF") != NULL && arg_vrf(c, p, "VRF", &vrf_id) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "MAX", &max_routes) < 0 && errno != ENOENT)
		return CMD_ERROR;

	struct gr_mpls_label_route_list_req req = {
		.vrf_id = vrf_id,
		.max_count = max_routes,
	};

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "VRF", GR_DISP_LEFT);
	gr_table_column(table, "LABEL", GR_DISP_RIGHT);
	gr_table_column(table, "NEXTHOP_ID", GR_DISP_RIGHT);
	gr_table_column(table, "ORIGIN", GR_DISP_LEFT);

	gr_api_client_stream_foreach (route, ret, c, GR_MPLS_LABEL_ROUTE_LIST, sizeof(req), &req) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, route->vrf_id));
		gr_table_cell(table, 1, "%u", route->in_label);
		gr_table_cell(table, 2, "%u", route->nh_id);
		gr_table_cell(table, 3, "%s", gr_nh_origin_name(route->origin));

		if (gr_table_print_row(table) < 0)
			break;
	}

	gr_table_free(table);

	if (ret < 0 && errno == EXFULL) {
		warnf("more routes not displayed");
		ret = 0;
	}

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

#define MPLS_CTX(root) CLI_CONTEXT(root, CTX_ARG("mpls", "MPLS label switching."))
#define MPLS_ROUTE_CTX(root) CLI_CONTEXT(MPLS_CTX(root), CTX_ARG("route", "Label routes."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		MPLS_ROUTE_CTX(root),
		"add LABEL nexthop id ID [vrf VRF]",
		mpls_route_add,
		"Add a label route.",
		with_help("MPLS label value (0-1048575).", ec_node_uint("LABEL", 0, 1048575, 10)),
		with_help("Nexthop user ID.", ec_node_uint("ID", 1, UINT32_MAX - 1, 10)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		MPLS_ROUTE_CTX(root),
		"del LABEL [vrf VRF]",
		mpls_route_del,
		"Delete a label route.",
		with_help("MPLS label value.", ec_node_uint("LABEL", 0, 1048575, 10)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		MPLS_ROUTE_CTX(root),
		"get LABEL [vrf VRF]",
		mpls_route_get,
		"Get a label route.",
		with_help("MPLS label value.", ec_node_uint("LABEL", 0, 1048575, 10)),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		MPLS_ROUTE_CTX(root),
		"[show] [(vrf VRF),(max MAX)]",
		mpls_route_list,
		"Show label routes.",
		with_help(
			"Max. number of routes to display (default 1000, use 0 for unlimited).",
			ec_node_uint("MAX", 0, UINT16_MAX, 10)
		),
		with_help("L3 routing domain name.", ec_node_dyn("VRF", complete_vrf_names, NULL))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static void mpls_event_print(uint32_t event, const void *obj) {
	const struct gr_mpls_label_route *r = obj;
	const char *action;

	switch (event) {
	case GR_EVENT_MPLS_ROUTE_ADD:
		action = "add";
		break;
	case GR_EVENT_MPLS_ROUTE_DEL:
		action = "del";
		break;
	default:
		action = "?";
		break;
	}

	printf("mpls route %s: vrf=%s label=%u nh_id=%u origin=%s\n",
	       action,
	       iface_name_from_id(NULL, r->vrf_id),
	       r->in_label,
	       r->nh_id,
	       gr_nh_origin_name(r->origin));
}

static struct cli_event_printer printer = {
	.name = "mpls_route",
	.print = mpls_event_print,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_MPLS_ROUTE_ADD,
		GR_EVENT_MPLS_ROUTE_DEL,
	},
};

static struct cli_context ctx = {
	.name = "mpls",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_event_printer_register(&printer);
}
