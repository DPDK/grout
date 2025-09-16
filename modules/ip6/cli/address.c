// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_event.h>
#include <gr_cli_iface.h>
#include <gr_ip6.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <stdint.h>

static cmd_status_t addr_add(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_addr_add_req req = {.exist_ok = true};
	struct gr_iface iface;

	if (arg_ip6_net(p, "IP6_NET", &req.addr.addr, false) < 0)
		return CMD_ERROR;
	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;
	req.addr.iface_id = iface.id;

	if (gr_api_client_send_recv(c, GR_IP6_ADDR_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t addr_del(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_addr_del_req req = {.missing_ok = true};
	struct gr_iface iface;

	if (arg_ip6_net(p, "IP6_NET", &req.addr.addr, false) < 0)
		return CMD_ERROR;
	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;
	req.addr.iface_id = iface.id;

	if (gr_api_client_send_recv(c, GR_IP6_ADDR_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t addr_list(struct gr_api_client *c, const struct ec_pnode *p) {
	struct libscols_table *table = scols_new_table();
	const struct gr_ip6_addr_list_resp *resp;
	struct gr_ip6_addr_list_req req = {0};
	struct gr_iface iface;
	void *resp_ptr = NULL;

	if (table == NULL)
		return CMD_ERROR;

	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	if (gr_api_client_send_recv(c, GR_IP6_ADDR_LIST, sizeof(req), &req, &resp_ptr) < 0) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	resp = resp_ptr;

	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "ADDRESS", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_addrs; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct gr_ip6_ifaddr *addr = &resp->addrs[i];
		if (iface_from_id(c, addr->iface_id, &iface) == 0)
			scols_line_sprintf(line, 0, "%s", iface.name);
		else
			scols_line_sprintf(line, 0, "%u", addr->iface_id);
		scols_line_sprintf(line, 1, IP6_F "/%hhu", &addr->addr, addr->addr.prefixlen);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		IP6_ADD_CTX(root),
		"address IP6_NET iface IFACE",
		addr_add,
		"Add an IPv6 address to an interface.",
		with_help("IPv6 address with prefix length.", ec_node_re("IP6_NET", IPV6_NET_RE)),
		with_help("Interface name.", ec_node_dyn("IFACE", complete_iface_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP6_DEL_CTX(root),
		"address IP6_NET iface IFACE",
		addr_del,
		"Remove an IPv6 address from an interface.",
		with_help("IPv6 address with prefix length.", ec_node_re("IP6_NET", IPV6_NET_RE)),
		with_help("Interface name.", ec_node_dyn("IFACE", complete_iface_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP6_SHOW_CTX(root),
		"address [vrf VRF]",
		addr_list,
		"Display all IPv6 addresses.",
		with_help("L3 addressing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "ipv6 address",
	.init = ctx_init,
};

static void addr_event_print(uint32_t event, const void *obj) {
	const struct gr_nexthop *nh = obj;
	const char *action;

	switch (event) {
	case GR_EVENT_IP6_ADDR_ADD:
		action = "add";
		break;
	case GR_EVENT_IP6_ADDR_DEL:
		action = "del";
		break;
	default:
		action = "?";
		break;
	}
	printf("addr6 %s: iface=%u " ADDR_F "/%hhu\n",
	       action,
	       nh->iface_id,
	       ADDR_W(nh->af),
	       &nh->addr,
	       nh->prefixlen);
}

static struct gr_cli_event_printer printer = {
	.print = addr_event_print,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IP6_ADDR_ADD,
		GR_EVENT_IP6_ADDR_DEL,
	},
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
	gr_cli_event_register_printer(&printer);
}
