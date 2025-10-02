// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_infra.h>
#include <gr_net_types.h>
#include <gr_table.h>

#include <ecoli.h>
#include <libsmartcols.h>

#include <inttypes.h>
#include <unistd.h>

static int stats_order_name(const void *sa, const void *sb) {
	const struct gr_infra_stat *a = sa;
	const struct gr_infra_stat *b = sb;
	return strncmp(a->name, b->name, sizeof(a->name));
}

static int stats_order_cycles(const void *sa, const void *sb) {
	const struct gr_infra_stat *a = sa;
	const struct gr_infra_stat *b = sb;
	if (a->cycles == b->cycles)
		return 0;
	if (a->cycles > b->cycles)
		return -1;
	return 1;
}

static int stats_order_packets(const void *sa, const void *sb) {
	const struct gr_infra_stat *a = sa;
	const struct gr_infra_stat *b = sb;

	if (a->objs == b->objs)
		return 0;
	if (a->objs > b->objs)
		return -1;
	return 1;
}

static cmd_status_t stats_get(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_stats_get_req req = {.flags = 0, .cpu_id = UINT16_MAX};
	bool brief = arg_str(p, "brief") != NULL;
	struct gr_infra_stats_get_resp *resp;
	void *resp_ptr = NULL;
	const char *pattern;

	if (arg_str(p, "software") != NULL)
		req.flags |= GR_INFRA_STAT_F_SW;
	else if (arg_str(p, "hardware") != NULL)
		req.flags |= GR_INFRA_STAT_F_HW;
	if (arg_str(p, "zero") != NULL)
		req.flags |= GR_INFRA_STAT_F_ZERO;
	pattern = arg_str(p, "PATTERN");
	if (pattern == NULL)
		pattern = "*";
	snprintf(req.pattern, sizeof(req.pattern), "%s", pattern);
	if (arg_u16(p, "CPU", &req.cpu_id) < 0 && errno != ENOENT)
		goto fail;

	if (gr_api_client_send_recv(c, GR_INFRA_STATS_GET, sizeof(req), &req, &resp_ptr) < 0)
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
	else if (req.flags & GR_INFRA_STAT_F_HW || brief)
		sort_func = stats_order_name;
	else
		sort_func = stats_order_cycles;

	if (req.flags & GR_INFRA_STAT_F_HW || brief) {
		qsort(resp->stats, resp->n_stats, sizeof(*resp->stats), sort_func);
		for (size_t i = 0; i < resp->n_stats; i++) {
			const struct gr_infra_stat *s = &resp->stats[i];
			if (req.flags & GR_INFRA_STAT_F_HW || brief)
				printf("%s %lu\n", s->name, s->objs);
		}
	} else {
		struct libscols_table *table = scols_new_table();

		scols_table_new_column(table, "NODE", 0, 0);
		scols_table_new_column(table, "CALLS", 0, SCOLS_FL_RIGHT);
		scols_table_new_column(table, "PACKETS", 0, SCOLS_FL_RIGHT);
		scols_table_new_column(table, "PKTS/CALL", 0, SCOLS_FL_RIGHT);
		scols_table_new_column(table, "CYCLES/CALL", 0, SCOLS_FL_RIGHT);
		scols_table_new_column(table, "CYCLES/PKT", 0, SCOLS_FL_RIGHT);
		scols_table_set_column_separator(table, "  ");

		qsort(resp->stats, resp->n_stats, sizeof(*resp->stats), sort_func);

		for (size_t i = 0; i < resp->n_stats; i++) {
			struct libscols_line *line = scols_table_new_line(table, NULL);
			double pkt_call = 0, cycles_pkt = 0, cycles_call = 0;
			const struct gr_infra_stat *s = &resp->stats[i];

			if (s->calls != 0) {
				pkt_call = ((double)s->objs) / ((double)s->calls);
				cycles_call = ((double)s->cycles) / ((double)s->calls);
			}
			if (s->objs != 0)
				cycles_pkt = ((double)s->cycles) / ((double)s->objs);

			scols_line_sprintf(line, 0, "%s", s->name);
			scols_line_sprintf(line, 1, "%lu", s->calls);
			scols_line_sprintf(line, 2, "%lu", s->objs);
			scols_line_sprintf(line, 3, "%.01f", pkt_call);
			scols_line_sprintf(line, 4, "%.01f", cycles_call);
			scols_line_sprintf(line, 5, "%.01f", cycles_pkt);
		}

		scols_print_table(table);
		scols_unref_table(table);
	}

	free(resp_ptr);
	return CMD_SUCCESS;
fail:
	free(resp_ptr);
	return CMD_ERROR;
}

static cmd_status_t stats_reset(struct gr_api_client *c, const struct ec_pnode *) {
	if (gr_api_client_send_recv(c, GR_INFRA_STATS_RESET, 0, NULL, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("stats", "Print statistics.")),
		"(software [brief])|hardware [zero,(pattern PATTERN),(cpu CPU),(order ORDER)]",
		stats_get,
		"Print statistics.",
		with_help("Print software stats.", ec_node_str("software", "software")),
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
					"Sort by decreasing number of cycles.",
					ec_node_str(EC_NO_ID, "cycles")
				)
			)
		)
	);
	if (ret < 0)
		return ret;
	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_CLEAR), "stats", stats_reset, "Reset all stats to zero."
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "stats",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
