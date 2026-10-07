// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "cli.h"
#include "display.h"

#include <gr_api.h>
#include <gr_string.h>

#include <ecoli.h>

#include <string.h>

static cmd_status_t log_packets_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_log_packets_set_req req = {.enabled = arg_str(p, "enable") != NULL};

	if (gr_api_client_send_recv(c, GR_LOG_PACKETS_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t log_level_set(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct ec_pnode *n = NULL;

	while ((n = ec_pnode_find_next(p, n, "EXPR", false)) != NULL) {
		struct gr_log_level_set_req req;
		const char *expr, *colon;
		int level;

		expr = ec_strvec_val(ec_pnode_get_strvec(n), 0);
		if (expr == NULL)
			continue;

		colon = strchr(expr, ':');
		if (colon == NULL) {
			errno = EINVAL;
			return CMD_ERROR;
		}

		size_t name_len = colon - expr;
		if (name_len >= sizeof(req.pattern)) {
			errno = ENAMETOOLONG;
			return CMD_ERROR;
		}

		snprintf(req.pattern, sizeof(req.pattern), "%.*s", (int)name_len, expr);

		level = gr_log_level_parse(colon + 1);
		if (level < 0)
			return CMD_ERROR;
		req.level = level;

		if (gr_api_client_send_recv(c, GR_LOG_LEVEL_SET, sizeof(req), &req, NULL) < 0)
			return CMD_ERROR;
	}

	return CMD_SUCCESS;
}

static cmd_status_t log_level_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_log_level_list_req req = {.show_all = arg_str(p, "all") != NULL};
	const struct gr_log_entry *entry;
	struct gr_table *table;
	int ret;

	table = gr_table_new();
	gr_table_column(table, "NAME", GR_DISP_LEFT);
	gr_table_column(table, "LEVEL", GR_DISP_LEFT);

	gr_api_client_stream_foreach (entry, ret, c, GR_LOG_LEVEL_LIST, sizeof(req), &req) {
		gr_table_cell(table, 0, "%s", entry->name);
		gr_table_cell(table, 1, "%s", gr_log_level_name(entry->level));
		if (gr_table_print_row(table) < 0)
			continue;
	}

	gr_table_free(table);

	return ret < 0 ? CMD_ERROR : CMD_SUCCESS;
}

static int complete_log_expr(
	struct gr_api_client *c,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void * /*cb_arg*/
) {
	const char *colon = strchr(arg, ':');
	struct ec_comp_item *o;
	char item[128];

	if (colon == NULL) {
		const struct gr_log_level_list_req req = {.show_all = true};
		const struct gr_log_entry *entry;
		int result = 0;
		int ret;

		gr_api_client_stream_foreach (entry, ret, c, GR_LOG_LEVEL_LIST, sizeof(req), &req) {
			snprintf(item, sizeof(item), "%s:", entry->name);
			if (ec_str_startswith(item, arg)) {
				if (!ec_comp_add_item(comp, node, EC_COMP_PARTIAL, arg, item))
					result = -1;
			}
		}
		return ret < 0 ? -1 : result;
	}

	const size_t prefix_len = colon - arg + 1;
	const char *level_part = colon + 1;

	for (unsigned i = GR_LOG_LEVEL_MIN; i <= GR_LOG_LEVEL_MAX; i++) {
		const char *name = gr_log_level_name(i);
		if (ec_str_startswith(name, level_part)) {
			snprintf(item, sizeof(item), "%.*s%s", (int)prefix_len, arg, name);
			o = ec_comp_add_item(comp, node, EC_COMP_FULL, arg, item);
			if (o == NULL)
				return -1;
			if (ec_comp_item_set_display(o, name) < 0)
				return -1;
		}
	}

	return 0;
}

static cmd_status_t log_rate_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_log_rate_set_req req;

	if (arg_u16(p, "RATE", &req.rate) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_LOG_RATE_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t log_rate_show(struct gr_api_client *c, const struct ec_pnode *) {
	const struct gr_log_rate_get_resp *resp;
	void *resp_ptr = NULL;
	struct gr_object *o;

	if (gr_api_client_send_recv(c, GR_LOG_RATE_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	o = gr_object_new(NULL);
	gr_object_field(o, "rate", GR_DISP_INT, "%u", resp->rate);
	gr_object_free(o);

	free(resp_ptr);
	return CMD_SUCCESS;
}

#define LOG_CTX(root) CLI_CONTEXT(root, CTX_ARG("log", "Logging."))
#define LOG_LEVEL_CTX(root) CLI_CONTEXT(LOG_CTX(root), CTX_ARG("level", "Logging levels."))
#define LOG_RATE_CTX(root) CLI_CONTEXT(LOG_CTX(root), CTX_ARG("rate", "Log rate limiting."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		LOG_CTX(root),
		"packets enable|disable",
		log_packets_set,
		"Control logging of ingress/egress packets.",
		with_help(
			"Enable logging of ingress/egress packets.", ec_node_str("enable", "enable")
		),
		with_help(
			"Disable logging of ingress/egress packets.",
			ec_node_str("disable", "disable")
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		LOG_LEVEL_CTX(root),
		"set EXPR+",
		log_level_set,
		"Set log level (e.g. grout.infra.port:debug).",
		with_help(
			"Log expression <pattern>:<level>.",
			ec_node_dyn("EXPR", complete_log_expr, NULL)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		LOG_LEVEL_CTX(root),
		"[show] [all]",
		log_level_show,
		"Show log types and their levels.",
		with_help("Include all DPDK log types.", ec_node_str("all", "all"))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		LOG_RATE_CTX(root),
		"set RATE",
		log_rate_set,
		"Set the max rate-limited log messages per second per stat (0 = unlimited).",
		with_help("Messages per second.", ec_node_uint("RATE", 0, UINT16_MAX, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		LOG_RATE_CTX(root),
		"[show]",
		log_rate_show,
		"Show the max rate-limited log messages per second per stat."
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "log",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
