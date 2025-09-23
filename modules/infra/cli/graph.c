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
	struct gr_infra_graph_dump_req req = {.flags = 0};
	void *resp_ptr = NULL;
	const char *dot;

	if (arg_str(p, "full"))
		req.flags |= GR_INFRA_GRAPH_DUMP_F_ERRORS;

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
		root,
		"graph show [brief|full]",
		graph_dump,
		"Show packet processing graph info (requires interfaces to be configured).",
		with_help("Hide error nodes (default).", ec_node_str("brief", "brief")),
		with_help("Show all nodes.", ec_node_str("full", "full"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "graph",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
