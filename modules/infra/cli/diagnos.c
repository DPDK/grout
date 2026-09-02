// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 SmartShare Systems

#include "cli.h"

#include <gr_api.h>
#include <gr_infra.h>

#include <ecoli.h>

#include <stdio.h>

static cmd_status_t obj_dump(struct gr_api_client *c, const struct ec_pnode *p) {
	const struct gr_diagnos_obj_dump_resp *resp = NULL;
	struct gr_diagnos_obj_dump_req req;
	const char *type = NULL;
	const char *name = NULL;
	int ret;

	if ((type = arg_str(p, "TYPE")) == NULL
	    || strlcpy(req.type, type, sizeof(req.type)) >= sizeof(req.type))
		return CMD_ERROR;

	*req.name = 0;
	if ((name = arg_str(p, "NAME")) != NULL
	    && strlcpy(req.name, name, sizeof(req.name)) >= sizeof(req.name))
		return CMD_ERROR;

	static_assert(sizeof(struct gr_diagnos_obj_dump_resp) == 0);

	gr_api_client_stream_foreach(resp, ret, c, GR_DIAGNOS_OBJ_DUMP, sizeof(req), &req) {
		fwrite(resp->text, 1, ret, stdout);
	}

	if (ret < 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

#define DIAGNOS_CTX(root) CLI_CONTEXT(root, CTX_ARG("diagnos", "Diagnostics (for developers)."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		DIAGNOS_CTX(root),
		"object dump TYPE [NAME]",
		obj_dump,
		"Dump object.",
		with_help("Object type.", ec_node("any", "TYPE")),
		with_help("Specific object.", ec_node("any", "NAME"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "diagnos",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
