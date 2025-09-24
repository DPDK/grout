// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_event.h>
#include <gr_cli_iface.h>
#include <gr_cli_l3.h>
#include <gr_cli_nexthop.h>
#include <gr_ip4.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>

static cmd_status_t route4_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_route_add_req req = {.exist_ok = true, .origin = GR_NH_ORIGIN_USER};

	if (arg_ip4_net(p, "DEST", &req.dest, true) < 0)
		return CMD_ERROR;
	if (arg_ip4(p, "NH", &req.nh) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "ID", &req.nh_id) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP4_ROUTE_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t route4_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_route_del_req req = {.missing_ok = true};

	if (arg_ip4_net(p, "DEST", &req.dest, true) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP4_ROUTE_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int route4_list(struct gr_api_client *c, uint16_t vrf_id, struct libscols_table *table) {
	struct gr_ip4_route_list_req req = {.vrf_id = vrf_id};
	const struct gr_ip4_route *route;
	char buf[128];
	int ret;

	gr_api_client_stream_foreach (route, ret, c, GR_IP4_ROUTE_LIST, sizeof(req), &req) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		scols_line_sprintf(line, 0, "%u", route->vrf_id);
		scols_line_sprintf(line, 1, IP4_F "/%hhu", &route->dest.ip, route->dest.prefixlen);
		if (cli_nexthop_format(buf, sizeof(buf), c, &route->nh, true) > 0)
			scols_line_set_data(line, 2, buf);
	}

	return ret;
}

static cmd_status_t route4_get(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_ip4_route_get_resp *resp;
	struct gr_ip4_route_get_req req = {0};
	void *resp_ptr = NULL;
	char buf[128];

	if (arg_ip4(p, "DEST", &req.dest) < 0)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP4_ROUTE_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	buf[0] = '\0';
	cli_nexthop_format(buf, sizeof(buf), c, &resp->nh, true);
	printf(IP4_F " via %s\n", &req.dest, buf);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static struct cli_route_ops route_ops = {
	.af = GR_AF_IP4,
	.add = route4_add,
	.del = route4_del,
	.list = route4_list,
	.get = route4_get,
};

static void route_event_print(uint32_t event, const void *obj) {
	const struct gr_ip4_route *r = obj;
	const char *action;
	char buf[128];

	switch (event) {
	case GR_EVENT_IP_ROUTE_ADD:
		action = "add";
		break;
	case GR_EVENT_IP_ROUTE_DEL:
		action = "del";
		break;
	default:
		action = "?";
		break;
	}

	buf[0] = '\0';
	cli_nexthop_format(buf, sizeof(buf), NULL, &r->nh, true);
	printf("route %s: vrf=%u " IP4_F "/%hhu via %s\n",
	       action,
	       r->vrf_id,
	       &r->dest.ip,
	       r->dest.prefixlen,
	       buf);
}

static struct cli_event_printer printer = {
	.print = route_event_print,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IP_ROUTE_ADD,
		GR_EVENT_IP_ROUTE_DEL,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_route_ops_register(&route_ops);
	cli_event_printer_register(&printer);
}
