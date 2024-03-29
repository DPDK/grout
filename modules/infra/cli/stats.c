// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_cli.h>
#include <br_client.h>
#include <br_infra.h>
#include <br_infra_msg.h>
#include <br_infra_types.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <unistd.h>

static int stats_order(const void *a, const void *b) {
	const struct br_infra_stat *stat_a = a;
	const struct br_infra_stat *stat_b = b;
	return strncmp(stat_a->name, stat_b->name, sizeof(stat_a->name));
}

static cmd_status_t stats_get(const struct br_client *c, const struct ec_pnode *p) {
	struct br_infra_stat *stats = NULL;
	br_infra_stats_flags_t flags = 0;
	const char *pattern;
	size_t len = 0;

	if (arg_str(p, "software") != NULL)
		flags |= BR_INFRA_STAT_F_SW;
	if (arg_str(p, "hardware") != NULL)
		flags |= BR_INFRA_STAT_F_HW;
	if (arg_str(p, "xstats") != NULL)
		flags |= BR_INFRA_STAT_F_XHW;
	if (arg_str(p, "all") != NULL)
		flags |= BR_INFRA_STAT_F_SW | BR_INFRA_STAT_F_HW | BR_INFRA_STAT_F_XHW;
	if (arg_str(p, "zero") != NULL)
		flags |= BR_INFRA_STAT_F_ZERO;
	pattern = arg_str(p, "PATTERN");
	if (pattern == NULL)
		pattern = "*";
	errno = 0;

	if (br_infra_stats_get(c, flags, pattern, &len, &stats) < 0)
		return CMD_ERROR;

	qsort(stats, len, sizeof(*stats), stats_order);

	for (size_t i = 0; i < len; i++) {
		struct br_infra_stat *s = &stats[i];
		printf("%s %lu\n", s->name, s->value);
	}

	free(stats);

	return CMD_SUCCESS;
}

static cmd_status_t stats_reset(const struct br_client *c, const struct ec_pnode *p) {
	(void)p;

	if (br_infra_stats_reset(c) < 0)
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
