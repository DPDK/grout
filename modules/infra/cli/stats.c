// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_api.h>
#include <br_cli.h>
#include <br_infra.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <unistd.h>

static int stats_order(const void *a, const void *b) {
	const struct br_infra_stat *stat_a = a;
	const struct br_infra_stat *stat_b = b;
	return strncmp(stat_a->name, stat_b->name, sizeof(stat_a->name));
}

static cmd_status_t stats_get(const struct br_api_client *c, const struct ec_pnode *p) {
	struct br_infra_stats_get_req req = {.flags = 0};
	struct br_infra_stats_get_resp *resp;
	void *resp_ptr = NULL;
	const char *pattern;

	if (arg_str(p, "software") != NULL)
		req.flags |= BR_INFRA_STAT_F_SW;
	if (arg_str(p, "hardware") != NULL)
		req.flags |= BR_INFRA_STAT_F_HW;
	if (arg_str(p, "xstats") != NULL)
		req.flags |= BR_INFRA_STAT_F_XHW;
	if (arg_str(p, "all") != NULL)
		req.flags |= BR_INFRA_STAT_F_SW | BR_INFRA_STAT_F_HW | BR_INFRA_STAT_F_XHW;
	if (arg_str(p, "zero") != NULL)
		req.flags |= BR_INFRA_STAT_F_ZERO;
	pattern = arg_str(p, "PATTERN");
	if (pattern == NULL)
		pattern = "*";
	snprintf(req.pattern, sizeof(req.pattern), "%s", pattern);

	if (br_api_client_send_recv(c, BR_INFRA_STATS_GET, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	qsort(resp->stats, resp->n_stats, sizeof(*resp->stats), stats_order);

	for (size_t i = 0; i < resp->n_stats; i++) {
		const struct br_infra_stat *s = &resp->stats[i];
		printf("%s %lu\n", s->name, s->value);
	}

	free(resp_ptr);

	return CMD_SUCCESS;
}

static cmd_status_t stats_reset(const struct br_api_client *c, const struct ec_pnode *p) {
	(void)p;

	if (br_api_client_send_recv(c, BR_INFRA_STATS_RESET, 0, NULL, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *stats = cli_context(root, "stats", "Manage statistics.");
	int ret;

	if (stats == NULL)
		return -1;

	ret = CLI_COMMAND(
		stats,
		"software|hardware|xstats|all [zero] [pattern PATTERN]",
		stats_get,
		"Print statistics.",
		with_help("Print software stats.", ec_node_str("software", "software")),
		with_help("Print hardware stats.", ec_node_str("hardware", "hardware")),
		with_help("Print extended driver stats.", ec_node_str("xstats", "xstats")),
		with_help("Print all stats.", ec_node_str("all", "all")),
		with_help("Print stats with value 0.", ec_node_str("zero", "zero")),
		with_help("Filter by glob pattern.", ec_node("any", "PATTERN"))
	);
	if (ret < 0)
		return ret;

	return CLI_COMMAND(stats, "reset", stats_reset, "Reset all stats to zero.");
}

static struct br_cli_context ctx = {
	.name = "stats",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
