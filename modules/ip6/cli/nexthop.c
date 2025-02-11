// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_clock.h>
#include <gr_ip6.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>
#include <stdint.h>

static cmd_status_t nh6_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_nh_add_req req = {0};
	struct gr_iface iface;

	if (inet_pton(AF_INET6, arg_str(p, "IP"), &req.nh.ipv6) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	if (arg_eth_addr(p, "MAC", &req.nh.mac) < 0)
		return CMD_ERROR;
	if (iface_from_name(c, arg_str(p, "IFACE"), &iface) < 0)
		return CMD_ERROR;
	req.nh.iface_id = iface.id;

	if (gr_api_client_send_recv(c, GR_IP6_NH_ADD, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t nh6_del(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_nh_del_req req = {.missing_ok = true};

	if (inet_pton(AF_INET6, arg_str(p, "IP"), &req.host) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_IP6_NH_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t nh6_list(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_nh_list_req req = {.vrf_id = UINT16_MAX};
	struct libscols_table *table = scols_new_table();
	const struct gr_ip6_nh_list_resp *resp;
	struct gr_iface iface;
	void *resp_ptr = NULL;
	char buf[128];
	clock_t now;
	ssize_t n;

	if (table == NULL)
		return CMD_ERROR;
	if (arg_u16(p, "VRF", &req.vrf_id) < 0 && errno != ENOENT) {
		scols_unref_table(table);
		return CMD_ERROR;
	}
	if (gr_api_client_send_recv(c, GR_IP6_NH_LIST, sizeof(req), &req, &resp_ptr) < 0) {
		scols_unref_table(table);
		return CMD_ERROR;
	}

	resp = resp_ptr;
	now = gr_clock_us();

	scols_table_new_column(table, "VRF", 0, 0);
	scols_table_new_column(table, "IP", 0, 0);
	scols_table_new_column(table, "MAC", 0, 0);
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "QUEUE", 0, 0);
	scols_table_new_column(table, "AGE", 0, 0);
	scols_table_new_column(table, "STATE", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_nhs; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct gr_nexthop *nh = &resp->nhs[i];

		n = 0;
		buf[0] = '\0';
		gr_nh_flags_foreach (f, nh->flags)
			SAFE_BUF(snprintf, sizeof(buf), "%s ", gr_nh_flag_name(f));
		if (n > 0)
			buf[n - 1] = '\0';

		scols_line_sprintf(line, 0, "%u", nh->vrf_id);
		scols_line_sprintf(line, 1, IP6_F, &nh->ipv6);
		if (nh->flags & GR_NH_F_REACHABLE) {
			scols_line_sprintf(line, 2, ETH_F, &nh->mac);
			if (iface_from_id(c, nh->iface_id, &iface) == 0)
				scols_line_sprintf(line, 3, "%s", iface.name);
			else
				scols_line_sprintf(line, 3, "%u", nh->iface_id);
			scols_line_sprintf(line, 4, "%u", nh->held_pkts);
			if (nh->flags & GR_NH_F_STATIC)
				scols_line_set_data(line, 5, "-");
			else
				scols_line_sprintf(
					line, 5, "%ld", (now - nh->last_reply) / CLOCKS_PER_SEC
				);
		} else {
			scols_line_set_data(line, 2, "??:??:??:??:??:??");
			scols_line_set_data(line, 3, "?");
			scols_line_sprintf(line, 4, "%u", nh->held_pkts);
			scols_line_set_data(line, 5, "?");
		}
		scols_line_sprintf(line, 6, "%s", buf);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
err:
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_ERROR;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		IP6_ADD_CTX(root),
		"nexthop IP mac MAC iface IFACE",
		nh6_add,
		"Add a new next hop.",
		with_help("IPv6 address.", ec_node_re("IP", IPV6_RE)),
		with_help("Ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),
		with_help("Output interface.", ec_node_dyn("IFACE", complete_iface_names, NULL))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP6_DEL_CTX(root),
		"nexthop IP [vrf VRF]",
		nh6_del,
		"Delete a next hop.",
		with_help("IPv6 address.", ec_node_re("IP", IPV6_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		IP6_SHOW_CTX(root),
		"nexthop [vrf VRF]",
		nh6_list,
		"List all next hops.",
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "ipv6 nexthop",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
