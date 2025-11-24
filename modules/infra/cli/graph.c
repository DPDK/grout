// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <stdio.h>
#include <unistd.h>

static cmd_status_t graph_dump(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_infra_graph_dump_req req = {0};
	void *resp_ptr = NULL;
	const char *dot;

	if (arg_str(p, "full"))
		req.full = true;
	if (arg_str(p, "compact"))
		req.compact = true;

	if (gr_api_client_send_recv(c, GR_INFRA_GRAPH_DUMP, sizeof(req), &req, &resp_ptr) < 0)
		return CMD_ERROR;

	dot = resp_ptr;
	printf("%s", dot);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("graph", "Packet processing graph")),
		"[show] [(brief|full),compact]",
		graph_dump,
		"Show packet processing graph info.",
		with_help("Hide error nodes (default).", ec_node_str("brief", "brief")),
		with_help("Show all nodes.", ec_node_str("full", "full")),
		with_help("Make the graph more compact.", ec_node_str("compact", "compact"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "graph",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
