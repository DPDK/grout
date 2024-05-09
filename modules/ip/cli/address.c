// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip.h"

#include <br_api.h>
#include <br_cli.h>
#include <br_ip4.h>
#include <br_net_types.h>
#include <br_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <stdint.h>

static cmd_status_t addr_add(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_ip4_addr_add_req req = {.exist_ok = true};

	if (br_ip4_net_parse(arg_str(p, "IP_NET"), &req.addr.addr, false) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "PORT_ID", &req.addr.port_id) < 0)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_IP4_ADDR_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t addr_del(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_ip4_addr_del_req req = {.missing_ok = true};

	if (br_ip4_net_parse(arg_str(p, "IP_NET"), &req.addr.addr, false) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "PORT_ID", &req.addr.port_id) < 0)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_IP4_ADDR_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t addr_list(const struct br_api_client *c, const struct ec_pnode *p) {
	struct libscols_table *table = scols_new_table();
	const struct br_ip4_addr_list_resp *resp;

	void *resp_ptr = NULL;
	char buf[BUFSIZ];

	(void)p;

	if (table == NULL)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_IP4_ADDR_LIST, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	scols_table_new_column(table, "PORT", 0, 0);
	scols_table_new_column(table, "ADDRESS", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_addrs; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct br_ip4_addr *addr = &resp->addrs[i];
		br_ip4_net_format(&addr->addr, buf, sizeof(buf));
		scols_line_sprintf(line, 0, "%u", addr->port_id);
		scols_line_sprintf(line, 1, "%s", buf);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		IP_ADD_CTX(root),
		"addr IP_NET port PORT_ID",
		addr_add,
		"Add an IPv4 address to a port.",
		with_help("IPv4 address with prefix length.", ec_node_re("IP_NET", IPV4_NET_RE)),
		with_help("Port ID.", ec_node_uint("PORT_ID", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP_DEL_CTX(root),
		"addr IP_NET port PORT_ID",
		addr_del,
		"Remove an IPv4 address from a port.",
		with_help("IPv4 address with prefix length.", ec_node_re("IP_NET", IPV4_NET_RE)),
		with_help("Port ID.", ec_node_uint("PORT_ID", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(IP_SHOW_CTX(root), "addr", addr_list, "Display all IPv4 addresses.");
	if (ret < 0)
		return ret;

	return 0;
}

static struct br_cli_context ctx = {
	.name = "ipv4 address",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
