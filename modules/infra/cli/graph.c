// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_api.h>
#include <br_cli.h>
#include <br_infra.h>
#include <br_net_types.h>
#include <br_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <stdio.h>
#include <unistd.h>

static cmd_status_t graph_dump(const struct br_api_client *c, const struct ec_pnode *p) {
	const struct br_infra_graph_dump_resp *resp;
	void *resp_ptr = NULL;

	(void)p;

	if (br_api_client_send_recv(c, BR_INFRA_GRAPH_DUMP, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	fwrite(resp->dot, 1, resp->len, stdout);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int stats_order(const void *sa, const void *sb) {
	const struct br_infra_graph_stat *a = sa;
	const struct br_infra_graph_stat *b = sb;
	if (a->cycles == b->cycles)
		return 0;
	if (a->cycles > b->cycles)
		return -1;
	return 1;
}

static cmd_status_t graph_stats(const struct br_api_client *c, const struct ec_pnode *p) {
	struct libscols_table *table = scols_new_table();
	struct br_infra_graph_stats_resp *resp;
	void *resp_ptr = NULL;
	bool zero = false;

	if (arg_str(p, "zero") != NULL)
		zero = true;

	if (br_api_client_send_recv(c, BR_INFRA_GRAPH_STATS, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	qsort(resp->stats, resp->n_stats, sizeof(*resp->stats), stats_order);

	scols_table_new_column(table, "NODE", 0, 0);
	scols_table_new_column(table, "CALLS", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "PACKETS", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "PKTS/CALL", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "CYCLES/CALL", 0, SCOLS_FL_RIGHT);
	scols_table_new_column(table, "CYCLES/PKT", 0, SCOLS_FL_RIGHT);
	scols_table_set_column_separator(table, "  ");

	for (size_t i = 0; i < resp->n_stats; i++) {
		struct libscols_line *line = scols_table_new_line(table, NULL);
		const struct br_infra_graph_stat *s = &resp->stats[i];
		double pkt_call = 0, cycles_pkt = 0, cycles_call = 0;

		if (s->calls != 0) {
			pkt_call = ((double)s->objects) / ((double)s->calls);
			cycles_call = ((double)s->cycles) / ((double)s->calls);
		}
		if (s->objects != 0)
			cycles_pkt = ((double)s->cycles) / ((double)s->objects);

		if (!zero && pkt_call == 0 && cycles_pkt == 0 && cycles_call == 0)
			continue;

		scols_line_sprintf(line, 0, "%s", s->node);
		scols_line_sprintf(line, 1, "%lu", s->calls);
		scols_line_sprintf(line, 2, "%lu", s->objects);
		scols_line_sprintf(line, 3, "%.01f", pkt_call);
		scols_line_sprintf(line, 4, "%.01f", cycles_call);
		scols_line_sprintf(line, 5, "%.01f", cycles_pkt);
	}

	scols_print_table(table);
	scols_unref_table(table);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("graph", "Show packet processing graph info.")),
		"dot",
		graph_dump,
		"Dump the graph in DOT format."
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("graph", "Show packet processing graph info.")),
		"stats [zero]",
		graph_stats,
		"Print graph nodes statistics.",
		with_help("Print stats with value 0.", ec_node_str("zero", "zero"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct br_cli_context ctx = {
	.name = "graph",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
