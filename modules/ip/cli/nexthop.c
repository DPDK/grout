// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip.h"

#include <br_api.h>
#include <br_cli.h>
#include <br_cli_iface.h>
#include <br_ip4.h>
#include <br_net_types.h>
#include <br_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>
#include <stdint.h>

static cmd_status_t nh4_add(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_ip4_nh_add_req req = {0};
	struct br_iface iface;

	if (inet_pton(AF_INET, arg_str(p, "IP"), &req.nh.host) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	if (br_eth_addr_parse(arg_str(p, "MAC"), &req.nh.mac) < 0)
		return CMD_ERROR;
	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;
	req.nh.iface_id = iface.id;

	if (br_api_client_send_recv(c, BR_IP4_NH_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t nh4_del(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_ip4_nh_del_req req = {.missing_ok = true};

	if (inet_pton(AF_INET, arg_str(p, "IP"), &req.host) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	if (br_api_client_send_recv(c, BR_IP4_NH_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t nh4_list(const struct br_api_client *c, const struct ec_pnode *p) {
	struct libscols_table *table = scols_new_table();
	const struct br_ip4_nh_list_resp *resp;
	char ip[BUFSIZ], state[BUFSIZ];
	struct br_iface iface;
	void *resp_ptr = NULL;
	ssize_t n;

	(void)p;

	if (table == NULL)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_IP4_NH_LIST, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;

	scols_table_new_column(table, "IP", 0, 0);
	scols_table_new_column(table, "MAC", 0, 0);
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "AGE", 0, 0);
	scols_table_new_column(table, "STATE", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_nhs; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct br_ip4_nh *nh = &resp->nhs[i];

		n = 0;
		state[0] = '\0';
		for (uint8_t i = 0; i < 16; i++) {
			br_ip4_nh_flags_t f = 1 << i;
			if (f & nh->flags) {
				n += snprintf(
					state + n, sizeof(state) - n, "%s ", br_ip4_nh_f_name(f)
				);
			}
		}
		if (n > 0)
			state[n - 1] = '\0';

		inet_ntop(AF_INET, &nh->host, ip, sizeof(ip));

		scols_line_sprintf(line, 0, "%s", ip);
		if (nh->flags & BR_IP4_NH_F_REACHABLE) {
			scols_line_sprintf(line, 1, ETH_ADDR_FMT, ETH_BYTES_SPLIT(nh->mac.bytes));
			if (iface_from_id(c, nh->iface_id, &iface) == 0)
				scols_line_sprintf(line, 2, "%s", iface.name);
			else
				scols_line_sprintf(line, 2, "%u", nh->iface_id);
			scols_line_sprintf(line, 3, "%u", nh->age);
		} else {
			scols_line_set_data(line, 1, "??:??:??:??:??:??");
			scols_line_set_data(line, 2, "?");
			scols_line_set_data(line, 3, "?");
		}
		scols_line_sprintf(line, 4, "%s", state);
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
		"nexthop IP mac MAC iface IFACE",
		nh4_add,
		"Add a new next hop.",
		with_help("IPv4 address.", ec_node_re("IP", IPV4_RE)),
		with_help("Ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help("Output interface.", ec_node_dyn("IFACE", complete_iface_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP_DEL_CTX(root),
		"nexthop IP",
		nh4_del,
		"Delete a next hop.",
		with_help("IPv4 address.", ec_node_re("IP", IPV4_RE))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(IP_SHOW_CTX(root), "nexthop", nh4_list, "List all next hops.");
	if (ret < 0)
		return ret;

	return 0;
}

static struct br_cli_context ctx = {
	.name = "ipv4 nexthop",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
