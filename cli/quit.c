// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <br_cli.h>
#include <br_client.h>

static cmd_status_t quit(const struct br_client *c, const struct ec_pnode *p) {
	(void)c;
	(void)p;
	return CMD_EXIT;
}

static int ctx_init(struct ec_node *root) {
	struct ec_node *n = NULL;

	n = CLI_COMMAND("quit", quit, "Exit the CLI.");
	if (n == NULL)
		goto fail;

	if (ec_node_or_add(root, n) < 0)
		goto fail;

	return 0;

fail:
	ec_node_free(n);
	return -1;
}

static struct br_cli_context ctx = {
	.name = "quit",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
