// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <stdio.h>
#include <unistd.h>

static cmd_status_t graph_dump(const struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_infra_graph_dump_resp *resp;
	void *resp_ptr = NULL;

	(void)p;

	if (gr_api_client_send_recv(c, GR_INFRA_GRAPH_DUMP, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	// strip the trailing NUL byte
	fwrite(resp->dot, 1, resp->len - 1, stdout);
	free(resp_ptr);

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("graph", "Show packet processing graph info.")),
		"dot",
		graph_dump,
		"Dump the graph in DOT format."
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
