// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "exec.h"

#include <gr_cli.h>

#include <ecoli.h>

#include <errno.h>

static STAILQ_HEAD(, gr_cli_context) contexts = STAILQ_HEAD_INITIALIZER(contexts);

void register_context(struct gr_cli_context *ctx) {
	STAILQ_INSERT_HEAD(&contexts, ctx, entries);
}

struct ec_node *init_commands(void) {
	struct gr_cli_context *ctx;
	struct ec_node *root;

	if ((root = ec_node("or", "grcli")) == NULL)
		goto fail;

	STAILQ_FOREACH (ctx, &contexts, entries) {
		if (ctx->init(root) < 0) {
			errorf("context init %s: %s", ctx->name, strerror(errno));
			goto fail;
		}
	}

	return root;
fail:
	ec_node_free(root);
	return NULL;
}

static cmd_cb_t *find_cmd_callback(struct ec_pnode *parsed) {
	const struct ec_pnode *p;

	for (p = parsed; p != NULL; p = EC_PNODE_ITER_NEXT(parsed, p, true)) {
		const struct ec_node *node = ec_pnode_get_node(p);
		cmd_cb_t *cb = ec_dict_get(ec_node_attrs(node), CALLBACK_ATTR);
		if (cb != NULL)
			return cb;
	}

	return NULL;
}

static exec_status_t exec_strvec(
	const struct gr_api_client *client,
	const struct ec_node *cmdlist,
	const struct ec_strvec *vec
) {
	struct ec_pnode *parsed = NULL;
	exec_status_t status;
	cmd_cb_t *cb;

	if ((parsed = ec_parse_strvec(cmdlist, vec)) == NULL) {
		status = EXEC_OTHER_ERROR;
		goto out;
	}
	if (!ec_pnode_matches(parsed) || ec_pnode_len(parsed) != ec_strvec_len(vec)) {
		status = EXEC_CMD_INVALID_ARGS;
		goto out;
	}
	if ((cb = find_cmd_callback(parsed)) == NULL) {
		status = EXEC_CB_UNDEFINED;
		goto out;
	}
	switch (cb(client, parsed)) {
	case CMD_SUCCESS:
		status = EXEC_SUCCESS;
		break;
	case CMD_EXIT:
		status = EXEC_CMD_EXIT;
		break;
	default:
		status = EXEC_CMD_FAILED;
		break;
	}
out:
	ec_pnode_free(parsed);
	return status;
}

exec_status_t
exec_line(const struct gr_api_client *client, const struct ec_node *cmdlist, const char *line) {
	exec_status_t status = EXEC_SUCCESS;
	struct ec_strvec *vec = NULL;

	errno = 0;
	if ((vec = ec_strvec_sh_lex_str(line, EC_STRVEC_STRICT, NULL)) == NULL) {
		if (errno == EBADMSG) {
			status = EXEC_LEX_ERROR;
		} else {
			status = EXEC_OTHER_ERROR;
		}
		goto out;
	}
	if (ec_strvec_len(vec) == 0) {
		status = EXEC_CMD_EMPTY;
		goto out;
	}
	status = exec_strvec(client, cmdlist, vec);
out:
	ec_strvec_free(vec);
	return status;
}

exec_status_t exec_args(
	const struct gr_api_client *client,
	const struct ec_node *cmdlist,
	size_t argc,
	const char *const *argv
) {
	exec_status_t status = EXEC_SUCCESS;
	struct ec_strvec *vec = NULL;

	if ((vec = ec_strvec_from_array(argv, argc)) == NULL) {
		status = EXEC_OTHER_ERROR;
		goto out;
	}
	if (ec_strvec_len(vec) == 0) {
		status = EXEC_CMD_EMPTY;
		goto out;
	}
	status = exec_strvec(client, cmdlist, vec);
out:
	ec_strvec_free(vec);
	return status;
}
