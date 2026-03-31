// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Maxime Leroy, Free Mobile

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_display.h>
#include <gr_infra.h>

#define FIB_POOL_CTX(root) CLI_CONTEXT(root, CTX_ARG("fib", "FIB"), CTX_ARG("pool", "tbl8 pool"))

static cmd_status_t fib_pool_show(struct gr_api_client *c, const struct ec_pnode *) {
	struct gr_fib_pool_stats_get_resp *resp;
	void *resp_ptr = NULL;

	if (gr_api_client_send_recv(c, GR_FIB_POOL_STATS_GET, 0, NULL, &resp_ptr) < 0)
		return CMD_ERROR;

	resp = resp_ptr;
	struct gr_object *o = gr_object_new(NULL);
	gr_object_field(o, "used", GR_DISP_INT, "%u", resp->used);
	gr_object_field(o, "total", GR_DISP_INT, "%u", resp->total);
	gr_object_field(o, "max", GR_DISP_INT, "%u", resp->max);
	gr_object_free(o);

	free(resp_ptr);
	return CMD_SUCCESS;
}

static cmd_status_t fib_pool_set(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_fib_pool_resize_req req = {0};

	if (arg_u32(p, "NUM_TBL8", &req.num_tbl8) < 0)
		return CMD_ERROR;

	if (gr_api_client_send_recv(c, GR_FIB_POOL_RESIZE, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		FIB_POOL_CTX(root),
		"set NUM_TBL8",
		fib_pool_set,
		"Resize the tbl8 pool.",
		with_help(
			"Target number of tbl8 groups.", ec_node_uint("NUM_TBL8", 1, UINT32_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		FIB_POOL_CTX(root), "[show]", fib_pool_show, "Show tbl8 pool statistics."
	);

	return ret;
}

static struct cli_context ctx = {
	.name = "fib_pool",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
