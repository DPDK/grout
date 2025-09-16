// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>

static cmd_status_t quit(struct gr_api_client *, const struct ec_pnode *) {
	return CMD_EXIT;
}

static int ctx_init(struct ec_node *root) {
	return CLI_COMMAND(root, "quit", quit, "Exit the CLI.");
}

static struct gr_cli_context ctx = {
	.name = "quit",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
