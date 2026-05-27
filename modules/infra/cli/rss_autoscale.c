// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Maxime Leroy, Free Mobile

#include "cli.h"
#include "cli_iface.h"
#include "display.h"

#include <gr_api.h>
#include <gr_infra.h>

#include <ecoli.h>

static cmd_status_t rss_autoscale_show(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_rss_autoscale_port_state *s;
	int ret;

	struct gr_table *table = gr_table_new();
	gr_table_column(table, "IFACE", GR_DISP_LEFT);
	gr_table_column(table, "N_ACTIVE", GR_DISP_RIGHT | GR_DISP_INT);
	gr_table_column(table, "N_WANTED", GR_DISP_RIGHT | GR_DISP_INT);
	gr_table_column(table, "CAP", GR_DISP_RIGHT);
	gr_table_column(table, "FLOOR", GR_DISP_RIGHT);
	gr_table_column(table, "MIN", GR_DISP_RIGHT | GR_DISP_INT);
	gr_table_column(table, "MAX", GR_DISP_RIGHT | GR_DISP_INT);

	gr_api_client_stream_foreach (s, ret, c, GR_RSS_AUTOSCALE_LIST, 0, NULL) {
		gr_table_cell(table, 0, "%s", iface_name_from_id(c, s->iface_id));
		gr_table_cell(table, 1, "%u", s->n_active);
		gr_table_cell(table, 2, "%u", s->n_load_recommended);
		if (s->cap == 0)
			gr_table_cell(table, 3, "-");
		else
			gr_table_cell(table, 3, "%u", s->cap);
		if (s->floor == 0)
			gr_table_cell(table, 4, "-");
		else
			gr_table_cell(table, 4, "%u", s->floor);
		gr_table_cell(table, 5, "%u", s->min_n);
		gr_table_cell(table, 6, "%u", s->max_n);

		if (gr_table_print_row(table) < 0)
			break;
	}

	gr_table_free(table);
	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

#define RSS_ARG CTX_ARG("rss-autoscale", "Adaptive RSS auto-scaling controller.")
#define RSS_CTX(root) CLI_CONTEXT(root, RSS_ARG)

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		RSS_CTX(root),
		"[show]",
		rss_autoscale_show,
		"Display adaptive RSS auto-scaling state per port."
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "infra rss-autoscale",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
