// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "br_infra_types.h"

#include <br_cli.h>
#include <br_client.h>
#include <br_infra.h>

#include <ecoli.h>

#include <stdint.h>

static void show(const struct br_infra_port *port) {
	if (port == NULL)
		return;
	printf("index: %u\n", port->index);
	printf("    device: %s\n", port->device);
	printf("    rx_queues: %u\n", port->n_rxq);
	printf("    tx_queues: %u\n", port->n_txq);
}

#define LIST_TITLE_FMT "%-12s  %-32s  %-12s  %s\n"
#define LIST_FMT "%-12u  %-32s  %-12u  %u\n"

static void list(const struct br_infra_port *port) {
	if (port == NULL)
		return;
	printf(LIST_FMT, port->index, port->device, port->n_rxq, port->n_txq);
}

static cmd_status_t port_add(const struct br_client *c, const struct ec_pnode *p) {
	const char *devargs = arg_str(p, "devargs");
	uint16_t port_id;

	if (br_infra_port_add(c, devargs, &port_id) < 0)
		return CMD_ERROR;

	printf("Created port %u\n", port_id);

	return CMD_SUCCESS;
}

static cmd_status_t port_set(const struct br_client *c, const struct ec_pnode *p) {
	uint64_t port_id, n_rxq;

	if (arg_uint(p, "index", &port_id) < 0)
		return CMD_ERROR;
	if (arg_uint(p, "n_rxq", &n_rxq) < 0)
		return CMD_ERROR;

	if (br_infra_port_set(c, port_id, n_rxq) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t port_del(const struct br_client *c, const struct ec_pnode *p) {
	uint64_t port_id;

	if (arg_uint(p, "index", &port_id) < 0)
		return CMD_ERROR;

	if (br_infra_port_del(c, port_id) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t port_show(const struct br_client *c, const struct ec_pnode *p) {
	struct br_infra_port port;
	uint64_t port_id;

	if (arg_uint(p, "index", &port_id) < 0)
		return CMD_ERROR;
	if (br_infra_port_get(c, port_id, &port) < 0)
		return CMD_ERROR;

	show(&port);

	return CMD_SUCCESS;
}

static cmd_status_t port_list(const struct br_client *c, const struct ec_pnode *p) {
	struct br_infra_port ports[32];
	size_t len;

	(void)p;

	if (br_infra_port_list(c, 32, ports, &len) < 0)
		return CMD_ERROR;

	printf(LIST_TITLE_FMT, "INDEX", "DEVICE", "RX_QUEUES", "TX_QUEUES");
	for (size_t i = 0; i < len; i++)
		list(&ports[i]);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *node = NULL;

	node = CLI_COMMAND_CONTEXT(
		"port",
		"Manage ports.",
		CLI_COMMAND(
			"add devargs",
			port_add,
			"Create a new port.",
			with_help("DPDK device args.", ec_node("devargs", "devargs"))
		),
		CLI_COMMAND(
			"set index rxqs n_rxq",
			port_set,
			"Create a new port.",
			with_help("Port index.", ec_node_uint("index", 0, UINT16_MAX - 1, 10)),
			with_help(
				"Number of Rx queues.", ec_node_uint("n_rxq", 0, UINT16_MAX - 1, 10)
			)
		),
		CLI_COMMAND(
			"del index",
			port_del,
			"Delete an existing port.",
			with_help("Port index.", ec_node_uint("index", 0, UINT16_MAX - 1, 10))
		),
		CLI_COMMAND(
			"show index",
			port_show,
			"Show one port details.",
			with_help("Port index.", ec_node_uint("index", 0, UINT16_MAX - 1, 10))
		),
		CLI_COMMAND("list", port_list, "List all ports.")
	);
	if (node == NULL)
		goto fail;

	if (ec_node_or_add(root, node) < 0)
		goto fail;

	return 0;

fail:
	ec_node_free(node);
	return -1;
}

static struct br_cli_context ctx = {
	.name = "port",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
