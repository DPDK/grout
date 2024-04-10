// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <br_api.h>
#include <br_cli.h>

static cmd_status_t quit(const struct br_api_client *c, const struct ec_pnode *p) {
	(void)c;
	(void)p;
	return CMD_EXIT;
}

static int ctx_init(struct ec_node *root) {
	return CLI_COMMAND(root, "quit", quit, "Exit the CLI.");
}

static struct br_cli_context ctx = {
	.name = "quit",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
