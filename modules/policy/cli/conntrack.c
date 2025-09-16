// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include "policy.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_clock.h>
#include <gr_conntrack.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <stdint.h>

static cmd_status_t conn_list(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_conntrack *conn;
	struct libscols_table *table;
	clock_t now;
	int ret;

	table = scols_new_table();
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "ID", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "STATE", 0, 0);
	scols_table_new_column(table, "FLOW", 0, 0);
	scols_table_new_column(table, "SRC", 0, 0);
	scols_table_new_column(table, "DST", 0, 0);
	scols_table_new_column(table, "PROTO", 0, 0);
	scols_table_new_column(table, "SPORT", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "DPORT", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "LAST_UPDATE", 0, SCOLS_FL_RIGHT);
	scols_table_set_column_separator(table, "  ");

	now = gr_clock_us();

	gr_api_client_stream_foreach (conn, ret, c, GR_CONNTRACK_LIST, 0, NULL) {
		struct libscols_line *fwd = scols_table_new_line(table, NULL);
		struct libscols_line *rev = scols_table_new_line(table, NULL);
		struct gr_iface iface;

		if (iface_from_id(c, conn->iface_id, &iface) < 0)
			scols_line_sprintf(fwd, 0, "%u", conn->iface_id);
		else
			scols_line_sprintf(fwd, 0, "%s", iface.name);

		scols_line_sprintf(fwd, 1, "0x%08x", conn->id);

		scols_line_sprintf(fwd, 2, "%s", gr_conn_state_name(conn->state));

		scols_line_set_data(fwd, 3, "fwd");
		scols_line_set_data(rev, 3, "rev");

		scols_line_sprintf(fwd, 4, IP4_F, &conn->fwd_flow.src);
		scols_line_sprintf(rev, 4, IP4_F, &conn->rev_flow.src);
		scols_line_sprintf(fwd, 5, IP4_F, &conn->fwd_flow.dst);
		scols_line_sprintf(rev, 5, IP4_F, &conn->rev_flow.dst);

		switch (conn->proto) {
		case IPPROTO_ICMP:
			scols_line_set_data(fwd, 6, "ICMP");
			break;
		case IPPROTO_TCP:
			scols_line_set_data(fwd, 6, "TCP");
			break;
		case IPPROTO_UDP:
			scols_line_set_data(fwd, 6, "UDP");
			break;
		}

		scols_line_sprintf(fwd, 7, "%u", ntohs(conn->fwd_flow.src_id));
		scols_line_sprintf(rev, 7, "%u", ntohs(conn->rev_flow.src_id));
		scols_line_sprintf(fwd, 8, "%u", ntohs(conn->fwd_flow.dst_id));
		scols_line_sprintf(rev, 8, "%u", ntohs(conn->rev_flow.dst_id));

		scols_line_sprintf(fwd, 9, "%lu", (now - conn->last_update) / 1000000);
	}

	scols_print_table(table);
	scols_unref_table(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static cmd_status_t conn_flush(struct gr_api_client *c, const struct ec_pnode *) {
	if (gr_api_client_send_recv(c, GR_CONNTRACK_FLUSH, 0, NULL, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t config_show(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_conntrack_conf_get_resp *resp;
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_CONNTRACK_CONF_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("used %u (%.01f%%)\n",
	       resp->used_count,
	       (100.0 * (float)resp->used_count) / (float)resp->max_count);
	printf("max %u\n", resp->max_count);
	printf("closed-timeout %u\n", resp->timeout_closed_sec);
	printf("new-timeout %u\n", resp->timeout_new_sec);
	printf("established-udp-timeout %u\n", resp->timeout_udp_established_sec);
	printf("established-tcp-timeout %u\n", resp->timeout_tcp_established_sec);
	printf("half-close-timeout %u\n", resp->timeout_half_close_sec);
	printf("time-wait-timeout %u\n", resp->timeout_time_wait_sec);

	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t config_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_conntrack_conf_set_req req = {0};

	if (arg_u32(p, "MAX", &req.max_count) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "CLOSED", &req.timeout_closed_sec) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "NEW", &req.timeout_new_sec) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "EST_UDP", &req.timeout_udp_established_sec) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "EST_TCP", &req.timeout_tcp_established_sec) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "HALF_CLOSE", &req.timeout_half_close_sec) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_u32(p, "TIME_WAIT", &req.timeout_time_wait_sec) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_CONNTRACK_CONF_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		POLICY_SHOW_CTX(root), "conntrack", conn_list, "Display tracked connections."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		POLICY_CLEAR_CTX(root), "conntrack", conn_flush, "Flush all tracked connections."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("config", "Change stack configuration.")),
		"conntrack (max MAX),(closed-timeout CLOSED),(new-timeout NEW),"
		"(established-udp-timeout EST_UDP),(established-tcp-timeout EST_TCP),"
		"(half-close-timeout HALF_CLOSE),(time-wait-timeout TIME_WAIT)",
		config_set,
		"Change the connection tracking configuration.",
		with_help(
			"Maximum number of tracked connections.",
			ec_node_uint("MAX", 1, UINT32_MAX, 10)
		),
		with_help(
			"Timeout after which idle & closed connections are destroyed.",
			ec_node_uint("CLOSED", 1, UINT32_MAX, 10)
		),
		with_help(
			"Timeout after which idle & new connections are destroyed.",
			ec_node_uint("NEW", 1, UINT32_MAX, 10)
		),
		with_help(
			"Timeout after which idle & established UDP connections are destroyed.",
			ec_node_uint("EST_UDP", 1, UINT32_MAX, 10)
		),
		with_help(
			"Timeout after which idle & established TCP connections are destroyed.",
			ec_node_uint("EST_TCP", 1, UINT32_MAX, 10)
		),
		with_help(
			"Timeout after which idle & half-close connections are destroyed.",
			ec_node_uint("HALF_CLOSE", 1, UINT32_MAX, 10)
		),
		with_help(
			"Timeout after which idle & time-wait connections are destroyed.",
			ec_node_uint("TIME_WAIT", 1, UINT32_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("config", "Show stack configuration.")),
		"conntrack",
		config_show,
		"Show the current connection tracking configuration.",
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "conntrack",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
