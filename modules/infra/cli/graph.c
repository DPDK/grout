// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "cli.h"
#include "display.h"

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <stdio.h>

static cmd_status_t graph_conf_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_graph_conf_set_req req = {.set_attrs = 0};

	if (arg_u16(p, "VECTOR", &req.vector_max) == 0)
		req.set_attrs |= GR_GRAPH_SET_VECTOR;
	else if (errno != ENOENT)
		return CMD_ERROR;

	if (arg_u16(p, "BURST", &req.rx_burst_max) == 0)
		req.set_attrs |= GR_GRAPH_SET_RX_BURST;
	else if (errno != ENOENT)
		return CMD_ERROR;

	if (arg_u16(p, "ICMP_ERROR_RATE", &req.icmp_error_rate) == 0)
		req.set_attrs |= GR_GRAPH_SET_ICMP_ERROR;
	else if (errno != ENOENT)
		return CMD_ERROR;

	if (arg_u16(p, "ARP_RATE", &req.arp_rate) == 0)
		req.set_attrs |= GR_GRAPH_SET_ARP;
	else if (errno != ENOENT)
		return CMD_ERROR;

	if (arg_u16(p, "ICMP_RATE", &req.icmp_rate) == 0)
		req.set_attrs |= GR_GRAPH_SET_ICMP;
	else if (errno != ENOENT)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_GRAPH_CONF_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t graph_conf_show(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_graph_conf *sizes;
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_GRAPH_CONF_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	sizes = resp_ptr;

	struct gr_object *o = gr_object_new(NULL);
	gr_object_field(o, "vector_max", GR_DISP_INT, "%u", sizes->vector_max);
	gr_object_field(o, "rx_burst_max", GR_DISP_INT, "%u", sizes->rx_burst_max);
	gr_object_field(o, "icmp_error_rate", GR_DISP_INT, "%u", sizes->icmp_error_rate);
	gr_object_field(o, "arp_rate", GR_DISP_INT, "%u", sizes->arp_rate);
	gr_object_field(o, "icmp_rate", GR_DISP_INT, "%u", sizes->icmp_rate);
	gr_object_free(o);

	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t graph_dump(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_graph_dump_req req = {0};
	void *resp_ptr = NULL;
	const char *dot;

	if (arg_str(p, "full"))
		req.full = true;
	if (arg_str(p, "layers"))
		req.by_layer = true;
	if (arg_str(p, "compact"))
		req.compact = true;

	if (gr_api_client_send_recv(c, GR_GRAPH_DUMP, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	dot = resp_ptr;
	printf("%s", dot);
	free(resp_ptr);

	return CMD_SUCCESS;
}

#define GRAPH_CTX(root) CLI_CONTEXT(root, CTX_ARG("graph", "Packet processing graph"))
#define CONF_CTX(root)                                                                             \
	CLI_CONTEXT(GRAPH_CTX(root), CTX_ARG("config", "Processing graph configuration."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CONF_CTX(root),
		"set (vector-max VECTOR),(rx-burst-max BURST),(icmp-error-rate ICMP_ERROR_RATE),"
		"(arp-rate ARP_RATE),(icmp-rate ICMP_RATE)",
		graph_conf_set,
		"Configure packet processing graph parameters.",
		with_help(
			"Maximum size of graph vectors.", ec_node_uint("VECTOR", 1, UINT16_MAX, 10)
		),
		with_help(
			"Maximum size of RX queue burst.", ec_node_uint("BURST", 1, UINT16_MAX, 10)
		),
		with_help(
			"ICMP errors/sec per node per worker (0 = no limit).",
			ec_node_uint("ICMP_ERROR_RATE", 0, UINT16_MAX, 10)
		),
		with_help(
			"ARP packets/sec per worker (0 = no limit).",
			ec_node_uint("ARP_RATE", 0, UINT16_MAX, 10)
		),
		with_help(
			"ICMP/ICMPv6 input packets/sec per worker (0 = no limit).",
			ec_node_uint("ICMP_RATE", 0, UINT16_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CONF_CTX(root),
		"[show]",
		graph_conf_show,
		"Show the current maximum burst sizes of the packet processing graph."
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		GRAPH_CTX(root),
		"[show] [(brief|full),layers,compact]",
		graph_dump,
		"Show packet processing graph info.",
		with_help("Hide error nodes (default).", ec_node_str("brief", "brief")),
		with_help("Show all nodes.", ec_node_str("full", "full")),
		with_help("Group nodes by network layer.", ec_node_str("layers", "layers")),
		with_help("Make the graph more compact.", ec_node_str("compact", "compact"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "graph",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
