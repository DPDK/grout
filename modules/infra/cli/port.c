// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "gr_cli_iface.h"

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_infra.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <errno.h>
#include <sys/queue.h>

static void port_show(const struct gr_api_client *, const struct gr_iface *iface) {
	const struct gr_iface_info_port *port = (const struct gr_iface_info_port *)iface->info;
	printf("devargs: %s\n", port->devargs);
	printf("mac: " ETH_ADDR_FMT "\n", ETH_BYTES_SPLIT(port->mac.bytes));
	printf("n_rxq: %u\n", port->n_rxq);
	printf("n_txq: %u\n", port->n_txq);
	printf("rxq_size: %u\n", port->rxq_size);
	printf("txq_size: %u\n", port->txq_size);
}

static void
port_list_info(const struct gr_api_client *, const struct gr_iface *iface, char *buf, size_t len) {
	const struct gr_iface_info_port *port = (const struct gr_iface_info_port *)iface->info;
	snprintf(
		buf,
		len,
		"devargs=%s mac=" ETH_ADDR_FMT,
		port->devargs,
		ETH_BYTES_SPLIT(port->mac.bytes)
	);
}

static struct cli_iface_type port_type = {
	.type_id = GR_IFACE_TYPE_PORT,
	.name = "port",
	.show = port_show,
	.list_info = port_list_info,
};

static uint64_t parse_port_args(
	const struct gr_api_client *c,
	const struct ec_pnode *p,
	struct gr_iface *iface,
	bool update
) {
	uint64_t set_attrs = parse_iface_args(c, p, iface, update);
	struct gr_iface_info_port *port;
	const char *devargs;

	port = (struct gr_iface_info_port *)iface->info;
	devargs = arg_str(p, "DEVARGS");
	if (devargs != NULL) {
		if (strlen(devargs) >= sizeof(port->devargs)) {
			errno = ENAMETOOLONG;
			goto err;
		}
		memccpy(port->devargs, devargs, 0, sizeof(port->devargs));
	}
	if (eth_addr_parse(arg_str(p, "MAC"), &port->mac) == 0)
		set_attrs |= GR_PORT_SET_MAC;

	if (arg_u16(p, "N_RXQ", &port->n_rxq) == 0)
		set_attrs |= GR_PORT_SET_N_RXQS;

	if (arg_u16(p, "Q_SIZE", &port->rxq_size) == 0) {
		port->txq_size = port->rxq_size;
		set_attrs |= GR_PORT_SET_Q_SIZE;
	}

	if (set_attrs == 0)
		errno = EINVAL;
	return set_attrs;
err:
	return 0;
}

static cmd_status_t port_add(const struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_infra_iface_add_resp *resp;
	struct gr_infra_iface_add_req req = {
		.iface = {.type = GR_IFACE_TYPE_PORT, .flags = GR_IFACE_F_UP}
	};
	void *resp_ptr = NULL;

	if (parse_port_args(c, p, &req.iface, false) == 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_ADD, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	printf("Created interface %u\n", resp->iface_id);
	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t port_set(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_iface_set_req req = {0};

	if ((req.set_attrs = parse_port_args(c, p, &req.iface, true)) == 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_IFACE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t rxq_set(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_rxq_set_req req;
	struct gr_iface iface;

	if (iface_from_name(c, arg_str(p, "NAME"), &iface) < 0)
		return CMD_ERROR;

	req.iface_id = iface.id;

	if (arg_u16(p, "RXQ", &req.rxq_id) < 0)
		return CMD_ERROR;
	if (arg_u16(p, "CPU", &req.cpu_id) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_RXQ_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int rxqs_order(const void *a, const void *b) {
	const struct gr_port_rxq_map *rxq_a = a;
	const struct gr_port_rxq_map *rxq_b = b;
	int v = rxq_a->iface_id - rxq_b->iface_id;
	if (v != 0)
		return v;
	v = rxq_a->rxq_id - rxq_b->rxq_id;
	if (v != 0)
		return v;
	return rxq_a->cpu_id - rxq_b->cpu_id;
}

static cmd_status_t rxq_list(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct libscols_table *table = scols_new_table();
	struct gr_infra_rxq_list_resp *resp;
	void *resp_ptr = NULL;

	(void)p;

	if (table == NULL)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_RXQ_LIST, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	qsort(resp->rxqs, resp->n_rxqs, sizeof(*resp->rxqs), rxqs_order);

	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "RXQ_ID", 0, 0);
	scols_table_new_column(table, "CPU_ID", 0, 0);
	scols_table_new_column(table, "ENABLED", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_rxqs; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct gr_port_rxq_map *q = &resp->rxqs[i];
		struct gr_iface iface;

		if (iface_from_id(c, q->iface_id, &iface) == 0)
			scols_line_sprintf(line, 0, "%s", iface.name);
		else
			scols_line_sprintf(line, 0, "%u", q->iface_id);
		scols_line_sprintf(line, 1, "%u", q->rxq_id);
		scols_line_sprintf(line, 2, "%u", q->cpu_id);
		scols_line_sprintf(line, 3, "%u", q->enabled);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

#define PORT_ATTRS_CMD IFACE_ATTRS_CMD ",(mac MAC),(rxqs N_RXQ),(qsize Q_SIZE)"

#define PORT_ATTRS_ARGS                                                                            \
	IFACE_ATTRS_ARGS, with_help("Set the ethernet address.", ec_node_re("MAC", ETH_ADDR_RE)),  \
		with_help("Number of Rx queues.", ec_node_uint("N_RXQ", 0, UINT16_MAX - 1, 10)),   \
		with_help("Rx/Tx queues size.", ec_node_uint("Q_SIZE", 0, UINT16_MAX - 1, 10))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ADD, CTX_ARG("interface", "Create interfaces.")),
		"port NAME devargs DEVARGS [" PORT_ATTRS_CMD "]",
		port_add,
		"Create a new port.",
		with_help("Interface name.", ec_node("any", "NAME")),
		with_help("DPDK device args.", ec_node("devargs", "DEVARGS")),
		PORT_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("interface", "Modify interfaces.")),
		"port NAME (name NEW_NAME)," PORT_ATTRS_CMD,
		port_set,
		"Modify port parameters.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		with_help("New interface name.", ec_node("any", "NEW_NAME")),
		PORT_ATTRS_ARGS
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("port", "Set DPDK port queue mapping.")),
		"qmap NAME rxq RXQ cpu CPU",
		rxq_set,
		"Set DPDK port queue mapping.",
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_PORT))
		),
		with_help("RX queue ID.", ec_node_uint("RXQ", 0, UINT16_MAX - 1, 10)),
		with_help("Worker CPU ID.", ec_node_uint("CPU", 0, UINT16_MAX - 1, 10))
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("port", "Display DPDK port information.")),
		"qmap",
		rxq_list,
		"Display DPDK port RXQ assignment."
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "infra port",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
	register_iface_type(&port_type);
}
