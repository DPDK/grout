// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <br_api.h>
#include <br_cli.h>
#include <br_infra.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <stdint.h>

static cmd_status_t port_add(const struct br_api_client *c, const struct ec_pnode *p) {
	const struct br_infra_port_add_resp *resp;
	struct br_infra_port_add_req req = {0};
	void *resp_ptr = NULL;

	memccpy(req.devargs, arg_str(p, "DEVARGS"), 0, sizeof(req.devargs));

	if (br_api_client_send_recv(c, BR_INFRA_PORT_ADD, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("Created port %u\n", resp->port_id);
	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t rxq_set(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_infra_rxq_set_req req;

	if (arg_u16(p, "INDEX", &req.port_id) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "RXQ", &req.rxq_id) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "CPU", &req.cpu_id) < 0)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_INFRA_RXQ_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t port_set(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_infra_port_set_req req = {0};

	if (arg_u16(p, "RXQ", &req.n_rxq) == 0)
		return rxq_set(c, p);

	if (arg_u16(p, "INDEX", &req.port_id) < 0)
		return CMD_ERROR;

	if (arg_u16(p, "N_RXQ", &req.n_rxq) < 0 && errno != ENOENT)
		return CMD_ERROR;
	else
		req.set_attrs |= BR_INFRA_PORT_N_RXQ;

	if (arg_u16(p, "Q_SIZE", &req.q_size) < 0 && errno != ENOENT)
		return CMD_ERROR;
	else
		req.set_attrs |= BR_INFRA_PORT_Q_SIZE;

	if (br_api_client_send_recv(c, BR_INFRA_PORT_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t port_del(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_infra_port_del_req req;

	if (arg_u16(p, "INDEX", &req.port_id) < 0)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_INFRA_PORT_DEL, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t port_list(const struct br_api_client *c, const struct ec_pnode *p) {
	const struct br_infra_port_list_resp *resp;
	void *resp_ptr = NULL;

	(void)p;

	if (br_api_client_send_recv(c, BR_INFRA_PORT_LIST, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("%-8s  %-20s  %-10s  %-10s  %-10s  %-10s  %s\n",
	       "INDEX",
	       "DEVICE",
	       "RX_QUEUES",
	       "RXQ_SIZE",
	       "TX_QUEUES",
	       "TXQ_SIZE",
	       "MAC");
	for (size_t i = 0; i < resp->n_ports; i++) {
		const struct br_infra_port *p = &resp->ports[i];
		printf("%-8u  %-20s  %-10u  %-10u  %-10u  %-10u  " ETH_ADDR_FMT "\n",
		       p->index,
		       p->device,
		       p->n_rxq,
		       p->rxq_size,
		       p->n_txq,
		       p->txq_size,
		       ETH_BYTES_SPLIT(p->mac.bytes));
	}

	free(resp_ptr);

	return CMD_SUCCESS;
}

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

static cmd_status_t port_show(const struct br_api_client *c, const struct ec_pnode *p) {
	const struct br_infra_port_get_resp *resp;
	struct br_infra_port_get_req req;
	void *resp_ptr = NULL;

	if (arg_str(p, "all") != NULL)
		return port_list(c, p);
	if (arg_str(p, "rxqs") != NULL)
		return rxq_list(c, p);
	if (arg_u16(p, "INDEX", &req.port_id) < 0)
		return CMD_ERROR;

	if (br_api_client_send_recv(c, BR_INFRA_PORT_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("index: %u\n", resp->port.index);
	printf("    device: %s\n", resp->port.device);
	printf("    rx_queues: %u\n", resp->port.n_rxq);
	printf("    rxq_size: %u\n", resp->port.rxq_size);
	printf("    tx_queues: %u\n", resp->port.n_txq);
	printf("    txq_size: %u\n", resp->port.txq_size);
	printf("    mac: " ETH_ADDR_FMT "\n", ETH_BYTES_SPLIT(resp->port.mac.bytes));

	free(resp_ptr);
	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD, CTX_ARG("port", "Create ports.")),
		"devargs DEVARGS",
		port_add,
		"Create a new physical port.",
		with_help("DPDK device args.", ec_node("devargs", "DEVARGS"))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("port", "Modify port properties.")),
		"index INDEX (rxqmap RXQ cpu CPU)|((numrxqs N_RXQ),(qsize Q_SIZE))",
		port_set,
		"Modify port parameters.",
		with_help("Port index.", ec_node_uint("INDEX", 0, UINT16_MAX - 1, 10)),
		with_help("Number of Rx queues.", ec_node_uint("N_RXQ", 0, UINT16_MAX - 1, 10)),
		with_help("Rx/Tx queues size.", ec_node_uint("Q_SIZE", 0, UINT16_MAX - 1, 10)),
		with_help("RX queue ID.", ec_node_uint("RXQ", 0, UINT16_MAX - 1, 10)),
		with_help("CPU ID.", ec_node_uint("CPU", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_DEL, CTX_ARG("port", "Delete ports.")),
		"index INDEX",
		port_del,
		"Delete an existing port.",
		with_help("Port index.", ec_node_uint("INDEX", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("port", "Display port details.")),
		"all|(index INDEX)|rxqs",
		port_show,
		"Show port details.",
		with_help("Show all ports.", ec_node_str("all", "all")),
		with_help("Show only this port.", ec_node_uint("INDEX", 0, UINT16_MAX - 1, 10)),
		with_help("Show port RX queues.", ec_node_str("rxqs", "rxqs"))
	);

	return 0;
}

static struct br_cli_context ctx = {
	.name = "infra port",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
