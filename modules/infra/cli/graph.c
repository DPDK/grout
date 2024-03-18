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

	(void)p;

	if (br_infra_graph_stats(c, &n_stats, &stats) < 0)
		return CMD_ERROR;

	qsort(stats, n_stats, sizeof(*stats), stats_order);

	printf("%-32s  %14s  %16s  %10s  %18s  %10s\n",
	       "NODE",
	       "CALLS",
	       "PACKETS",
	       "PKTS/CALL",
	       "CYCLES",
	       "CYCLES/PKT");

	for (size_t i = 0; i < n_stats; i++) {
		struct br_infra_graph_stat *s = &stats[i];
		double pkt_call = 0, cycles_pkt = 0;

		if (s->calls != 0)
			pkt_call = ((double)s->objects) / ((double)s->calls);
		if (s->objects != 0)
			cycles_pkt = ((double)s->cycles) / ((double)s->objects);

		printf("%-32s  %14lu  %16lu  %10.01f  %18lu  %10.01f\n",
		       s->node,
		       s->calls,
		       s->objects,
		       pkt_call,
		       s->cycles,
		       cycles_pkt);
	}

	free(stats);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *node = NULL;

	node = CLI_COMMAND_CONTEXT(
		"graph",
		"Get information about the packet processing graph.",
		CLI_COMMAND("dump", graph_dump, "Dump the graph in DOT format."),
		CLI_COMMAND("stats", graph_stats, "Print graph nodes statistics.")
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
	.name = "graph",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
