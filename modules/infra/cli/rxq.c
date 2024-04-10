// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_api.h>
#include <br_cli.h>
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

static cmd_status_t rxq_list(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_infra_rxq_list_resp *resp;
	void *resp_ptr = NULL;

	(void)p;

	if (br_api_client_send_recv(c, BR_INFRA_RXQ_LIST, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	qsort(resp->rxqs, resp->n_rxqs, sizeof(*resp->rxqs), rxqs_order);

	printf("%-8s  %-8s  %-8s  %s\n", "PORT", "RXQ_ID", "CPU_ID", "ENABLED");
	for (size_t i = 0; i < resp->n_rxqs; i++) {
		const struct br_infra_rxq *q = &resp->rxqs[i];
		printf("%-8u  %-8u  %-8u  %u\n", q->port_id, q->rxq_id, q->cpu_id, q->enabled);
	}

	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t rxq_set(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_infra_rxq_set_req req;

	if (arg_u16(p, "PORT", &req.port_id) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "RXQ", &req.rxq_id) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "CPU", &req.cpu_id) < 0)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_INFRA_RXQ_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *rxq = cli_context(root, "rxq", "Manage port RX queues.");
	unsigned ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	if (rxq == NULL)
		return -1;

	if (CLI_COMMAND(rxq, "list", rxq_list, "List all RX queues.") < 0)
		return -1;

	return CLI_COMMAND(
		rxq,
		"set port PORT rxq RXQ cpu CPU",
		rxq_set,
		"Assign an RX queue to a given CPU.",
		with_help("Port index.", ec_node_uint("PORT", 0, UINT16_MAX - 1, 10)),
		with_help("RX queue ID.", ec_node_uint("RXQ", 0, UINT16_MAX - 1, 10)),
		with_help("CPU ID.", ec_node_uint("CPU", 0, ncpus - 1, 10))
	);
}

static struct br_cli_context ctx = {
	.name = "rxq",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
