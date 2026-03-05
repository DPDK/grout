// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_display.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <inttypes.h>
#include <string.h>
#include <unistd.h>

static int stats_order_name(const void *sa, const void *sb) {
	const struct gr_stat *a = sa;
	const struct gr_stat *b = sb;
	return strncmp(a->name, b->name, sizeof(a->name));
}

static int stats_order_cycles(const void *sa, const void *sb) {
	const struct gr_stat *a = sa;
	const struct gr_stat *b = sb;
	if (a->cycles == b->cycles)
		return 0;
	if (a->cycles > b->cycles)
		return -1;
	return 1;
}

static int stats_order_packets(const void *sa, const void *sb) {
	const struct gr_stat *a = sa;
	const struct gr_stat *b = sb;

	if (a->packets == b->packets)
		return 0;
	if (a->packets > b->packets)
		return -1;
	return 1;
}

static int stats_order_topo(const void *sa, const void *sb) {
	const struct gr_stat *a = sa;
	const struct gr_stat *b = sb;

	if (a->topo_order == b->topo_order)
		return 0;
	if (a->topo_order > b->topo_order)
		return 1;
	return -1;
}

static cmd_status_t stats_get(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_stats_get_req req = {.flags = 0, .cpu_id = UINT16_MAX};
	bool brief = arg_str(p, "brief") != NULL;
	struct gr_stats_get_resp *resp;
	void *resp_ptr = NULL;
	const char *pattern;

	if (arg_str(p, "hardware") != NULL)
		req.flags |= GR_STATS_F_HW;
	else
		req.flags |= GR_STATS_F_SW;
	if (arg_str(p, "zero") != NULL)
		req.flags |= GR_STATS_F_ZERO;
	pattern = arg_str(p, "PATTERN");
	if (pattern == NULL)
		pattern = "*";
	snprintf(req.pattern, sizeof(req.pattern), "%s", pattern);
	if (arg_u16(p, "CPU", &req.cpu_id) < 0 && errno != ENOENT)
		goto fail;

	if (gr_api_client_send_recv(c, GR_STATS_GET, sizeof(req), &req, &resp_ptr) < 0)
		goto fail;

	resp = resp_ptr;

	int (*sort_func)(const void *, const void *);
	const char *order = arg_str(p, "ORDER") ?: "";
	if (strcmp(order, "name") == 0)
		sort_func = stats_order_name;
	else if (strcmp(order, "cycles") == 0)
		sort_func = stats_order_cycles;
	else if (strcmp(order, "packets") == 0)
		sort_func = stats_order_packets;
	else if (strcmp(order, "graph") == 0)
		sort_func = stats_order_topo;
	else if (req.flags & GR_STATS_F_HW || brief)
		sort_func = stats_order_name;
	else
		sort_func = stats_order_cycles;

	if (req.flags & GR_STATS_F_HW || brief) {
		qsort(resp->stats, resp->n_stats, sizeof(*resp->stats), sort_func);
		struct gr_object *o = gr_object_new();
		for (size_t i = 0; i < resp->n_stats; i++) {
			const struct gr_stat *s = &resp->stats[i];
			if (req.flags & GR_STATS_F_HW || brief)
				gr_object_field(o, s->name, GR_DISP_INT, "%lu", s->packets);
		}
		gr_object_free(o);
	} else {
		struct gr_table *table = gr_table_new();
		gr_table_column(table, "NODE", GR_DISP_LEFT); // 0
		gr_table_column(table, "BATCHES", GR_DISP_RIGHT | GR_DISP_INT); // 1
		gr_table_column(table, "PACKETS", GR_DISP_RIGHT | GR_DISP_INT); // 2
		gr_table_column(table, "PKTS/BATCH", GR_DISP_RIGHT | GR_DISP_FLOAT); // 3
		gr_table_column(table, "CYCLES/BATCH", GR_DISP_RIGHT | GR_DISP_FLOAT); // 4
		gr_table_column(table, "CYCLES/PKT", GR_DISP_RIGHT | GR_DISP_FLOAT); // 5

		qsort(resp->stats, resp->n_stats, sizeof(*resp->stats), sort_func);

		for (size_t i = 0; i < resp->n_stats; i++) {
			double pkt_call = 0, cycles_pkt = 0, cycles_call = 0;
			const struct gr_stat *s = &resp->stats[i];

			if (s->batches != 0) {
				pkt_call = ((double)s->packets) / ((double)s->batches);
				cycles_call = ((double)s->cycles) / ((double)s->batches);
			}
			if (s->packets != 0)
				cycles_pkt = ((double)s->cycles) / ((double)s->packets);

			gr_table_cell(table, 0, "%s", s->name);
			gr_table_cell(table, 1, "%lu", s->batches);
			gr_table_cell(table, 2, "%lu", s->packets);
			gr_table_cell(table, 3, "%.01f", pkt_call);
			gr_table_cell(table, 4, "%.01f", cycles_call);
			gr_table_cell(table, 5, "%.01f", cycles_pkt);

			if (gr_table_print_row(table) < 0)
				continue;
		}

		gr_table_free(table);
	}

	free(resp_ptr);
	return CMD_SUCCESS;
fail:
	free(resp_ptr);
	return CMD_ERROR;
}

static cmd_status_t stats_reset(struct gr_api_client *c, const struct ec_pnode *) {
	if (gr_api_client_send_recv(c, GR_STATS_RESET, 0, NULL, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define STATS_CTX(root) CLI_CONTEXT(root, CTX_ARG("stats", "Packet processing statistics."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(STATS_CTX(root), "reset", stats_reset, "Reset all stats to zero.");
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		STATS_CTX(root),
		"[show] [(software|hardware),brief,zero,(pattern PATTERN),(cpu CPU),(order ORDER)]",
		stats_get,
		"Print statistics.",
		with_help("Print software stats (default).", ec_node_str("software", "software")),
		with_help("Print hardware stats.", ec_node_str("hardware", "hardware")),
		with_help("Only print packet counts.", ec_node_str("brief", "brief")),
		with_help(
			"Only return stats from one CPU.",
			ec_node_uint("CPU", 0, UINT16_MAX - 1, 10)
		),
		with_help("Print stats with value 0.", ec_node_str("zero", "zero")),
		with_help("Filter by glob pattern.", ec_node("any", "PATTERN")),
		with_help(
			"Ordering.",
			EC_NODE_OR(
				"ORDER",
				with_help("Sort by stat name.", ec_node_str(EC_NO_ID, "name")),
				with_help(
					"Sort by decreasing number of packets.",
					ec_node_str(EC_NO_ID, "packets")
				),
				with_help(
					"Sort by graph topological order.",
					ec_node_str(EC_NO_ID, "graph")
				),
				with_help(
					"Sort by decreasing number of cycles.",
					ec_node_str(EC_NO_ID, "cycles")
				)
			)
		)
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "stats",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
