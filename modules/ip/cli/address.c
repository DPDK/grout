// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "cli.h"
#include "cli_event.h"
#include "cli_iface.h"
#include "cli_l3.h"
#include "display.h"

#include <gr_api.h>
#include <gr_ip4.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <stdint.h>

static cmd_status_t addr_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_addr_add_req req = {.exist_ok = true};

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.addr.iface_id) < 0)
		return CMD_ERROR;
	if (arg_ip4_net(p, "ADDR", &req.addr.addr, false) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP4_ADDR_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t addr_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_addr_del_req req = {.missing_ok = true};

	if (arg_iface(c, p, "IFACE", GR_IFACE_TYPE_UNDEF, &req.addr.iface_id) < 0)
		return CMD_ERROR;
	if (arg_ip4_net(p, "ADDR", &req.addr.addr, false) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP4_ADDR_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int addr_flush(struct gr_api_client *c, uint16_t iface_id) {
	struct gr_ip4_addr_flush_req req = {.iface_id = iface_id};

	return gr_api_client_send_recv(c, GR_IP4_ADDR_FLUSH, sizeof(req), &req, NULL);
}

static int addr_list(struct gr_api_client *c, uint16_t iface_id, struct gr_table *table) {
	struct gr_ip4_addr_list_req req = {.vrf_id = GR_VRF_ID_UNDEF, .iface_id = iface_id};
	const struct gr_ip4_ifaddr *addr;
	int ret;

	gr_api_client_stream_foreach (addr, ret, c, GR_IP4_ADDR_LIST, sizeof(req), &req) {
		if (iface_id != GR_IFACE_ID_UNDEF && addr->iface_id != iface_id)
			continue;

		gr_table_cell(table, 0, "%s", iface_name_from_id(c, addr->iface_id));
		gr_table_cell(table, 1, "%s", gr_af_name(GR_AF_IP4));
		gr_table_cell(table, 2, IP4_NET_F, &addr->addr);

		if (gr_table_print_row(table) < 0)
			break;
	}

	return ret;
}

static struct cli_addr_ops addr_ops = {
	.af = GR_AF_IP4,
	.add = addr_add,
	.del = addr_del,
	.list = addr_list,
	.flush = addr_flush,
};

static void addr_event_print(uint32_t event, const void *obj) {
	const struct gr_ip4_ifaddr *ifa = obj;
	const char *action;

	switch (event) {
	case GR_EVENT_IP_ADDR_ADD:
		action = "add";
		break;
	case GR_EVENT_IP_ADDR_DEL:
		action = "del";
		break;
	default:
		action = "?";
		break;
	}
	printf("addr4 %s: iface=%s " IP4_NET_F "\n",
	       action,
	       iface_name_from_id(NULL, ifa->iface_id),
	       &ifa->addr);
}

static struct cli_event_printer printer = {
	.name = "addr4",
	.print = addr_event_print,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IP_ADDR_ADD,
		GR_EVENT_IP_ADDR_DEL,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_addr_ops_register(&addr_ops);
	cli_event_printer_register(&printer);
}
