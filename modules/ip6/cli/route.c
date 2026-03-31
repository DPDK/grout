// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_event.h>
#include <gr_cli_iface.h>
#include <gr_cli_l3.h>
#include <gr_cli_nexthop.h>
#include <gr_display.h>
#include <gr_ip6.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>

static cmd_status_t route6_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_route_add_req req = {.exist_ok = true, .origin = GR_NH_ORIGIN_STATIC};

	if (arg_ip6_net(p, "DEST", &req.dest, true) < 0)
		return CMD_ERROR;
	if (arg_ip6(p, "NH", &req.nh) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "ID", &req.nh_id) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_vrf(c, p, "VRF", &req.vrf_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_ROUTE_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route6_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_route_del_req req = {.missing_ok = true};

	if (arg_ip6_net(p, "DEST", &req.dest, true) < 0)
		return CMD_ERROR;
	if (arg_vrf(c, p, "VRF", &req.vrf_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_ROUTE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int
route6_list(struct gr_api_client *c, uint16_t vrf_id, struct gr_table *table, uint16_t max) {
	struct gr_ip6_route_list_req req = {.vrf_id = vrf_id, .max_count = max};
	const struct gr_ip6_route *route;
	char buf[128];
	int ret, num;

	num = 0;
	gr_api_client_stream_foreach (route, ret, c, GR_IP6_ROUTE_LIST, sizeof(req), &req) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, route->vrf_id));
		gr_table_cell(table, 1, "%s", gr_af_name(GR_AF_IP6));
		gr_table_cell(table, 2, IP6_NET_F, &route->dest);
		gr_table_cell(table, 3, "%s", gr_nh_origin_name(route->origin));
		if (cli_nexthop_format(buf, sizeof(buf), c, &route->nh, true) > 0)
			gr_table_cell(table, 4, "%s", buf);

		if (gr_table_print_row(table) < 0)
			break;

		num++;
	}

	return ret < 0 ? ret : num;
}

static cmd_status_t route6_get(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_ip6_route_get_resp *resp;
	struct gr_ip6_route_get_req req = {0};
	void *resp_ptr = NULL;

	if (arg_ip6(p, "DEST", &req.dest) < 0)
		return CMD_ERROR;
	if (arg_vrf(c, p, "VRF", &req.vrf_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_ROUTE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	struct gr_object *o = gr_object_new(NULL);
	gr_object_field(o, "destination", 0, IP6_F, &req.dest);
	gr_object_open(o, "nexthop");
	cli_nexthop_fill_object(o, c, &resp->nh, true);
	gr_object_close(o);
	gr_object_free(o);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t route6_config_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_fib_default_set_req req = {0};

	arg_u32(p, "RIB6_ROUTES", &req.max_routes);

	if (gr_api_client_send_recv(c, GR_IP6_FIB_DEFAULT_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int route6_config_show(struct gr_api_client *c, uint16_t vrf_id, struct gr_table *table) {
	struct gr_ip6_fib_info_list_req req = {.vrf_id = vrf_id};
	const struct gr_fib6_info *info;
	int ret;

	gr_api_client_stream_foreach (info, ret, c, GR_IP6_FIB_INFO_LIST, sizeof(req), &req) {
		if (info->vrf_id == GR_VRF_ID_UNDEF) {
			gr_table_cell(table, 0, "default");
		} else {
			gr_table_cell(table, 0, "%s", iface_name_from_id(c, info->vrf_id));
		}
		gr_table_cell(table, 1, "%s", gr_af_name(GR_AF_IP6));
		gr_table_cell(
			table,
			2,
			"%u/%u (%.1f%%)",
			info->used_routes,
			info->max_routes,
			info->max_routes ? 100.0 * info->used_routes / info->max_routes : 0
		);

		if (gr_table_print_row(table) < 0)
			break;
	}

	return ret;
}

static struct cli_route_ops route_ops = {
	.af = GR_AF_IP6,
	.add = route6_add,
	.del = route6_del,
	.list = route6_list,
	.get = route6_get,
	.config_set = route6_config_set,
	.config_show = route6_config_show,
};

static void route_event_print(uint32_t event, const void *obj) {
	const struct gr_ip6_route *r = obj;
	const char *action;
	char buf[128];

	switch (event) {
	case GR_EVENT_IP6_ROUTE_ADD:
		action = "add";
		break;
	case GR_EVENT_IP6_ROUTE_DEL:
		action = "del";
		break;
	default:
		action = "?";
		break;
	}

	buf[0] = '\0';
	cli_nexthop_format(buf, sizeof(buf), NULL, &r->nh, true);
	printf("route6 %s: vrf=%u " IP6_NET_F " origin=%s via %s\n",
	       action,
	       r->vrf_id,
	       &r->dest,
	       gr_nh_origin_name(r->origin),
	       buf);
}

static struct cli_event_printer printer = {
	.print = route_event_print,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IP6_ROUTE_ADD,
		GR_EVENT_IP6_ROUTE_DEL,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_route_ops_register(&route_ops);
	cli_event_printer_register(&printer);
}
