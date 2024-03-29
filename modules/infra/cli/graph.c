// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_cli.h>
#include <br_client.h>
#include <br_infra.h>
#include <br_infra_msg.h>
#include <br_infra_types.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <stdio.h>
#include <unistd.h>

static cmd_status_t graph_dump(const struct br_client *c, const struct ec_pnode *p) {
	char *dot = NULL;
	size_t len = 0;

	(void)p;

	if (br_infra_graph_dump(c, &len, &dot) < 0)
		return CMD_ERROR;

	fwrite(dot, 1, len, stdout);
	free(dot);

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

static cmd_status_t graph_stats(const struct br_client *c, const struct ec_pnode *p) {
	struct br_infra_graph_stat *stats = NULL;
	size_t n_stats = 0;
	bool zero = false;

	if (arg_str(p, "zero") != NULL)
		zero = true;

	if (br_infra_graph_stats(c, &n_stats, &stats) < 0)
		return CMD_ERROR;

	qsort(stats, n_stats, sizeof(*stats), stats_order);

	printf("%-32s  %14s  %16s  %12s  %12s  %12s\n",
	       "NODE",
	       "CALLS",
	       "PACKETS",
	       "PKTS/CALL",
	       "CYCLES/CALL",
	       "CYCLES/PKT");

	for (size_t i = 0; i < n_stats; i++) {
		struct br_infra_graph_stat *s = &stats[i];
		double pkt_call = 0, cycles_pkt = 0, cycles_call = 0;

		if (s->calls != 0) {
			pkt_call = ((double)s->objects) / ((double)s->calls);
			cycles_call = ((double)s->cycles) / ((double)s->calls);
		}
		if (s->objects != 0)
			cycles_pkt = ((double)s->cycles) / ((double)s->objects);

		if (!zero && pkt_call == 0 && cycles_pkt == 0 && cycles_call == 0)
			continue;

		printf("%-32s  %14lu  %16lu  %12.01f  %12.01f  %12.01f\n",
		       s->node,
		       s->calls,
		       s->objects,
		       pkt_call,
		       cycles_call,
		       cycles_pkt);
	}

	free(stats);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *graph = cli_context(
		root, "graph", "Get information about the packet processing graph."
	);
	if (graph == NULL)
		return -1;
	if (CLI_COMMAND(graph, "dump", graph_dump, "Dump the graph in DOT format.") < 0)
		return -1;
	return CLI_COMMAND(
		graph,
		"stats [zero]",
		graph_stats,
		"Print graph nodes statistics.",
		with_help("Print stats with value 0.", ec_node_str("zero", "zero"))
	);
}

static struct br_cli_context ctx = {
	.name = "graph",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
