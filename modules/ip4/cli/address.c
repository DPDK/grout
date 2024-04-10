// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_api.h>
#include <br_cli.h>
#include <br_ip4.h>
#include <br_net_types.h>

#include <ecoli.h>

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
	const struct br_ip4_addr_list_resp *resp;
	void *resp_ptr = NULL;
	char buf[BUFSIZ];

	(void)p;

	if (br_api_client_send_recv(c, BR_IP4_ADDR_LIST, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	printf("%-10s  %s\n", "PORT", "ADDRESS");
	for (size_t i = 0; i < resp->n_addrs; i++) {
		const struct br_ip4_addr *addr = &resp->addrs[i];
		br_ip4_net_format(&addr->addr, buf, sizeof(buf));
		printf("%-10u  %s\n", addr->port_id, buf);
	}

	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *ipv4 = cli_context(root, "ipv4", "Manage IPv4 stack.");
	struct ec_node *addr = cli_context(ipv4, "addr", "Manage IPv4 local addresses.");
	int ret;

	if (ipv4 == NULL || addr == NULL)
		return -1;

	ret = CLI_COMMAND(
		addr,
		"add IP_NET port PORT_ID",
		addr_add,
		"Add an address to a port.",
		with_help("IPv4 address with prefix length.", ec_node_re("IP_NET", IPV4_NET_RE)),
		with_help("Port ID.", ec_node_uint("PORT_ID", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		addr,
		"del IP_NET port PORT_ID",
		addr_del,
		"Remove an address from a port.",
		with_help("IPv4 address with prefix length.", ec_node_re("IP_NET", IPV4_NET_RE)),
		with_help("Port ID.", ec_node_uint("PORT_ID", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	return CLI_COMMAND(addr, "list", addr_list, "List all addresses.");
}

static struct br_cli_context ctx = {
	.name = "ipv4 address",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
