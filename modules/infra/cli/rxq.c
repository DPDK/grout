// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_infra_types.h"

#include <br_cli.h>
#include <br_client.h>
#include <br_infra.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <stdint.h>
#include <unistd.h>

static int rxqs_order(const void *a, const void *b) {
	const struct br_infra_rxq *rxq_a = a;
	const struct br_infra_rxq *rxq_b = b;
	int v = rxq_a->port_id - rxq_b->port_id;
	if (v != 0)
		return v;
	v = rxq_a->rxq_id - rxq_b->rxq_id;
	if (v != 0)
		return v;
	return rxq_a->cpu_id - rxq_b->cpu_id;
}

static cmd_status_t rxq_list(const struct br_client *c, const struct ec_pnode *p) {
	struct br_infra_rxq *rxqs = NULL;
	size_t len = 0;

	(void)p;

	if (br_infra_rxq_list(c, &len, &rxqs) < 0)
		return CMD_ERROR;

	qsort(rxqs, len, sizeof(*rxqs), rxqs_order);

	printf("%-8s  %-8s  %-8s  %s\n", "PORT", "RXQ_ID", "CPU_ID", "ENABLED");
	for (size_t i = 0; i < len; i++) {
		struct br_infra_rxq *q = &rxqs[i];
		printf("%-8u  %-8u  %-8u  %u\n", q->port_id, q->rxq_id, q->cpu_id, q->enabled);
	}

	free(rxqs);

	return CMD_SUCCESS;
}

static cmd_status_t rxq_set(const struct br_client *c, const struct ec_pnode *p) {
	uint64_t port_id, rxq_id, cpu_id;

	if (arg_uint(p, "PORT", &port_id) < 0)
		return CMD_ERROR;
	if (arg_uint(p, "RXQ", &rxq_id) < 0)
		return CMD_ERROR;
	if (arg_uint(p, "CPU", &cpu_id) < 0)
		return CMD_ERROR;

	if (br_infra_rxq_set(c, port_id, rxq_id, cpu_id) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	unsigned ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	struct ec_node *node = NULL;

	node = CLI_COMMAND_CONTEXT(
		"rxq",
		"Manage ports RX queues.",
		CLI_COMMAND("list", rxq_list, "List all RX queues."),
		CLI_COMMAND(
			"set port PORT rxq RXQ cpu CPU",
			rxq_set,
			"Assign an RX queue to a given CPU.",
			with_help("Port index.", ec_node_uint("PORT", 0, UINT16_MAX - 1, 10)),
			with_help("RX queue ID.", ec_node_uint("RXQ", 0, UINT16_MAX - 1, 10)),
			with_help("CPU ID.", ec_node_uint("CPU", 0, ncpus - 1, 10))
		)
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
	.name = "rxq",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
