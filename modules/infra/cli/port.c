// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br_infra_types.h"

#include <br_cli.h>
#include <br_client.h>
#include <br_infra.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <stdint.h>

static cmd_status_t port_add(const struct br_client *c, const struct ec_pnode *p) {
	const char *devargs = arg_str(p, "DEVARGS");
	uint16_t port_id;

	if (br_infra_port_add(c, devargs, &port_id) < 0)
		return CMD_ERROR;

	printf("Created port %u\n", port_id);

	return CMD_SUCCESS;
}

static cmd_status_t port_set(const struct br_client *c, const struct ec_pnode *p) {
	uint64_t port_id, n_rxq, q_size;

	n_rxq = 0;
	q_size = 0;

	if (arg_uint(p, "INDEX", &port_id) < 0)
		return CMD_ERROR;
	if (arg_uint(p, "N_RXQ", &n_rxq) < 0 && errno != ENOENT)
		return CMD_ERROR;
	if (arg_uint(p, "Q_SIZE", &q_size) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (br_infra_port_set(c, port_id, n_rxq, q_size) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t port_del(const struct br_client *c, const struct ec_pnode *p) {
	uint64_t port_id;

	if (arg_uint(p, "INDEX", &port_id) < 0)
		return CMD_ERROR;

	if (br_infra_port_del(c, port_id) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t port_show(const struct br_client *c, const struct ec_pnode *p) {
	struct br_infra_port port;
	uint64_t port_id;

	if (arg_uint(p, "INDEX", &port_id) < 0)
		return CMD_ERROR;
	if (br_infra_port_get(c, port_id, &port) < 0)
		return CMD_ERROR;

	printf("index: %u\n", port.index);
	printf("    device: %s\n", port.device);
	printf("    rx_queues: %u\n", port.n_rxq);
	printf("    rxq_size: %u\n", port.rxq_size);
	printf("    tx_queues: %u\n", port.n_txq);
	printf("    txq_size: %u\n", port.txq_size);
	printf("    mac: " ETH_ADDR_FMT "\n", ETH_BYTES_SPLIT(port.mac.bytes));

	return CMD_SUCCESS;
}

static cmd_status_t port_list(const struct br_client *c, const struct ec_pnode *p) {
	struct br_infra_port *ports = NULL;
	size_t len = 0;

	(void)p;

	if (br_infra_port_list(c, &len, &ports) < 0)
		return CMD_ERROR;

	printf("%-8s  %-20s  %-10s  %-10s  %-10s  %-10s  %s\n",
	       "INDEX",
	       "DEVICE",
	       "RX_QUEUES",
	       "RXQ_SIZE",
	       "TX_QUEUES",
	       "TXQ_SIZE",
	       "MAC");
	for (size_t i = 0; i < len; i++) {
		struct br_infra_port *p = &ports[i];
		printf("%-8u  %-20s  %-10u  %-10u  %-10u  %-10u  " ETH_ADDR_FMT "\n",
		       p->index,
		       p->device,
		       p->n_rxq,
		       p->rxq_size,
		       p->n_txq,
		       p->txq_size,
		       ETH_BYTES_SPLIT(p->mac.bytes));
	}

	free(ports);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *node = NULL;

	node = CLI_COMMAND_CONTEXT(
		"port",
		"Manage ports.",
		CLI_COMMAND(
			"add DEVARGS",
			port_add,
			"Create a new port.",
			with_help("DPDK device args.", ec_node("devargs", "DEVARGS"))
		),
		CLI_COMMAND(
			"set INDEX [rxqs N_RXQ] [qsize Q_SIZE]",
			port_set,
			"Modify port parameters.",
			with_help("Port index.", ec_node_uint("INDEX", 0, UINT16_MAX - 1, 10)),
			with_help(
				"Number of Rx queues.", ec_node_uint("N_RXQ", 0, UINT16_MAX - 1, 10)
			),
			with_help(
				"Rx/Tx queues size.", ec_node_uint("Q_SIZE", 0, UINT16_MAX - 1, 10)
			)
		),
		CLI_COMMAND(
			"del INDEX",
			port_del,
			"Delete an existing port.",
			with_help("Port index.", ec_node_uint("INDEX", 0, UINT16_MAX - 1, 10))
		),
		CLI_COMMAND(
			"show INDEX",
			port_show,
			"Show one port details.",
			with_help("Port index.", ec_node_uint("INDEX", 0, UINT16_MAX - 1, 10))
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
