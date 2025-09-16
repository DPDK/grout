// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_infra.h>
#include <gr_string.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

static cmd_status_t affinity_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_cpu_affinity_set_req req = {0};
	const char *arg;

	if ((arg = arg_str(p, "CONTROL")) != NULL) {
		if (cpuset_parse(&req.control_cpus, arg) < 0)
			return CMD_ERROR;
	}
	if ((arg = arg_str(p, "DATAPATH")) != NULL) {
		if (cpuset_parse(&req.datapath_cpus, arg) < 0)
			return CMD_ERROR;
	}

	if (gr_api_client_send_recv(c, GR_INFRA_CPU_AFFINITY_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t affinity_show(struct gr_api_client *c, const struct ec_pnode *) {
	struct gr_infra_cpu_affinity_get_resp resp;
	void *resp_ptr = NULL;
	char buf[BUFSIZ];

	if (gr_api_client_send_recv(c, GR_INFRA_CPU_AFFINITY_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	memcpy(&resp, resp_ptr, sizeof(resp));
	free(resp_ptr);

	if (cpuset_format(buf, sizeof(buf), &resp.control_cpus) < 0)
		return CMD_ERROR;

	printf("control-cpus %s\n", buf);

	if (cpuset_format(buf, sizeof(buf), &resp.datapath_cpus) < 0)
		return CMD_ERROR;

	printf("datapath-cpus %s\n", buf);

	return CMD_SUCCESS;
}

static cmd_status_t rxq_set(struct gr_api_client *c, const struct ec_pnode *p) {
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
	int v = rxq_a->cpu_id - rxq_b->cpu_id;
	if (v != 0)
		return v;
	v = rxq_a->iface_id - rxq_b->iface_id;
	if (v != 0)
		return v;
	return rxq_a->rxq_id - rxq_b->rxq_id;
}

static cmd_status_t rxq_list(struct gr_api_client *c, const struct ec_pnode *) {
	struct libscols_table *table = scols_new_table();
	struct gr_infra_rxq_list_resp *resp;
	void *resp_ptr = NULL;

	if (table == NULL)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_INFRA_RXQ_LIST, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	qsort(resp->rxqs, resp->n_rxqs, sizeof(*resp->rxqs), rxqs_order);

	scols_table_new_column(table, "CPU_ID", 0, 0);
	scols_table_new_column(table, "IFACE", 0, 0);
	scols_table_new_column(table, "RXQ_ID", 0, 0);
	scols_table_new_column(table, "ENABLED", 0, 0);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_rxqs; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct gr_port_rxq_map *q = &resp->rxqs[i];
		struct gr_iface iface;

		scols_line_sprintf(line, 0, "%u", q->cpu_id);
		if (iface_from_id(c, q->iface_id, &iface) == 0)
			scols_line_sprintf(line, 1, "%s", iface.name);
		else
			scols_line_sprintf(line, 1, "%u", q->iface_id);
		scols_line_sprintf(line, 2, "%u", q->rxq_id);
		scols_line_sprintf(line, 3, "%u", q->enabled);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

#define CPU_LIST_RE "^[0-9,-]+$"

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("affinity", "Configure CPU affinity.")),
		"cpus (control CONTROL),(datapath DATAPATH)",
		affinity_set,
		"Change the CPU affinity lists.",
		with_help(
			"CPUs reserved for control plane threads.",
			ec_node_re("CONTROL", CPU_LIST_RE)
		),
		with_help(
			"CPUs reserved for datapath worker threads.",
			ec_node_re("DATAPATH", CPU_LIST_RE)
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("affinity", "Display CPU affinity.")),
		"cpus",
		affinity_show,
		"Display CPU affinity lists."
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SET, CTX_ARG("affinity", "Configure CPU affinity.")),
		"qmap NAME rxq RXQ cpu CPU",
		rxq_set,
		"Set DPDK port queue affinity.",
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
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("affinity", "Display CPU affinity.")),
		"qmap",
		rxq_list,
		"Display DPDK port RXQ affinity."
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "infra affinity",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
