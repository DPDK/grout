// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_clock.h>
#include <gr_conntrack.h>
#include <gr_display.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <stdint.h>

static cmd_status_t conn_list(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_conntrack *conn;
	clock_t now;
	int ret;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "IFACE", GR_DISP_LEFT); // 0
	gr_table_column(table, "ID", GR_DISP_RIGHT); // 1
	gr_table_column(table, "STATE", GR_DISP_LEFT); // 2
	gr_table_column(table, "FLOW", GR_DISP_LEFT); // 3
	gr_table_column(table, "SRC", GR_DISP_LEFT); // 4
	gr_table_column(table, "DST", GR_DISP_LEFT); // 5
	gr_table_column(table, "PROTO", GR_DISP_LEFT); // 6
	gr_table_column(table, "SPORT", GR_DISP_RIGHT | GR_DISP_INT); // 7
	gr_table_column(table, "DPORT", GR_DISP_RIGHT | GR_DISP_INT); // 8
	gr_table_column(table, "LAST_UPDATE", GR_DISP_RIGHT); // 9

	now = gr_clock_us();

	gr_api_client_stream_foreach (conn, ret, c, GR_CONNTRACK_LIST, 0, NULL) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, conn->iface_id));
		gr_table_cell(table, 1, "0x%08x", conn->id);
		gr_table_cell(table, 2, "%s", gr_conn_state_name(conn->state));
		gr_table_cell(table, 3, "fwd");
		gr_table_cell(table, 4, IP4_F, &conn->fwd_flow.src);
		gr_table_cell(table, 5, IP4_F, &conn->fwd_flow.dst);

		switch (conn->proto) {
		case IPPROTO_ICMP:
			gr_table_cell(table, 6, "ICMP");
			break;
		case IPPROTO_TCP:
			gr_table_cell(table, 6, "TCP");
			break;
		case IPPROTO_UDP:
			gr_table_cell(table, 6, "UDP");
			break;
		}

		gr_table_cell(table, 7, "%u", ntohs(conn->fwd_flow.src_id));
		gr_table_cell(table, 8, "%u", ntohs(conn->fwd_flow.dst_id));
		gr_table_cell(table, 9, "%lu", (now - conn->last_update) / 1000000);

		if (gr_table_print_row(table) < 0)
			continue;

		gr_table_cell(table, 3, "rev");
		gr_table_cell(table, 4, IP4_F, &conn->rev_flow.src);
		gr_table_cell(table, 5, IP4_F, &conn->rev_flow.dst);
		gr_table_cell(table, 7, "%u", ntohs(conn->rev_flow.src_id));
		gr_table_cell(table, 8, "%u", ntohs(conn->rev_flow.dst_id));

		if (gr_table_print_row(table) < 0)
			continue;
	}

	gr_table_free(table);

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

#define CONNTRACK_ARG CTX_ARG("conntrack", "Connection tracking.")
#define CONNTRACK_CTX(root) CLI_CONTEXT(root, CONNTRACK_ARG)
#define CONNTRACK_CONFIG_CTX(root)                                                                 \
	CLI_CONTEXT(root, CONNTRACK_ARG, CTX_ARG("config", "Conntrack configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CONNTRACK_CTX(root), "flush", conn_flush, "Flush all tracked connections."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CONNTRACK_CONFIG_CTX(root),
		"set (max MAX),(closed-timeout CLOSED),(new-timeout NEW),"
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
		CONNTRACK_CONFIG_CTX(root),
		"[show]",
		config_show,
		"Show the current connection tracking configuration."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(CONNTRACK_CTX(root), "[show]", conn_list, "Display tracked connections.");
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "conntrack",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
