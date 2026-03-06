// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>

#include <ecoli.h>

static cmd_status_t log_packets_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_log_packets_set_req req = {.enabled = arg_str(p, "enable") != NULL};

	if (gr_api_client_send_recv(c, GR_LOG_PACKETS_SET, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define LOG_CTX(root) CLI_CONTEXT(root, CTX_ARG("log", "Logging."))

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

	return 0;
}

static struct cli_context ctx = {
	.name = "log",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
