// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "exec.h"
#include "log.h"

#include <gr_cli.h>
#include <gr_macro.h>

#include <ecoli.h>

#include <errno.h>
#include <string.h>

static STAILQ_HEAD(, cli_context) contexts = STAILQ_HEAD_INITIALIZER(contexts);

void cli_context_register(struct cli_context *ctx) {
	STAILQ_INSERT_HEAD(&contexts, ctx, next);
}

struct ec_node *init_commands(void) {
	struct cli_context *ctx;
	struct ec_node *root;

	if ((root = ec_node("or", "grcli")) == NULL)
		goto fail;

	STAILQ_FOREACH (ctx, &contexts, next) {
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

static cmd_cb_t find_cmd_callback(struct ec_pnode *parsed) {
	const struct ec_pnode *p;

	for (p = parsed; p != NULL; p = EC_PNODE_ITER_NEXT(parsed, p, true)) {
		const struct ec_node *node = ec_pnode_get_node(p);
		cmd_cb_t cb = ec_dict_get(ec_node_attrs(node), CALLBACK_ATTR);
		if (cb != NULL)
			return cb;
	}

	return errno_set_null(EOPNOTSUPP);
}

static struct ec_strvec *
get_suggestions(const struct ec_node *cmdlist, const char *cmdline, unsigned *pos) {
	struct ec_strvec *args = NULL;
	struct ec_strvec *sug = NULL;
	struct ec_comp *c = NULL;

	if (cmdlist == NULL || cmdline == NULL || pos == NULL) {
		errno = EINVAL;
		goto out;
	}

	if ((args = ec_strvec_sh_lex_str(cmdline, EC_STRVEC_TRAILSP, NULL)) == NULL)
		goto out;

	while (ec_strvec_len(args) > 0) {
		unsigned i = ec_strvec_len(args) - 1;
		const struct ec_dict *attrs;

		if ((attrs = ec_strvec_get_attrs(args, i)) == NULL)
			goto out;

		*pos = (uintptr_t)ec_dict_get(attrs, EC_STRVEC_ATTR_START);

		if ((c = ec_complete_strvec(cmdlist, args)) == NULL)
			goto out;

		if (ec_comp_count(c, EC_COMP_FULL) == 0
		    && strcmp(ec_strvec_val(args, i), "") != 0) {
			ec_comp_free(c);
			c = NULL;
			// Replace argument with an empty one to ensure we get
			// all available completion items.
			ec_strvec_del_last(args);
			ec_strvec_add(args, "");
			if ((c = ec_complete_strvec(cmdlist, args)) == NULL)
				goto out;
		}

		if (ec_comp_count(c, EC_COMP_FULL) > 0) {
			sug = ec_strvec();
			if (sug == NULL)
				goto out;

			struct ec_comp_item *i;
			EC_COMP_FOREACH(i, c, EC_COMP_FULL) {
				if (ec_strvec_add(sug, ec_comp_item_get_str(i)) < 0)
					goto out;
			}

			goto out;
		}
		ec_comp_free(c);
		c = NULL;
		ec_strvec_del_last(args);
	}

out:
	ec_comp_free(c);
	ec_strvec_free(args);
	return sug;
}

static void print_suggestions(const struct ec_node *cmdlist, const struct ec_strvec *cmd) {
	struct ec_strvec *sug = NULL;
	unsigned pos = 0;
	char buf[BUFSIZ];
	size_t n = 0;

	// Rebuild a string from the arguments to allow printing the full command.
	for (unsigned i = 0; i < ec_strvec_len(cmd); i++) {
		const char *arg = ec_strvec_val(cmd, i);
		const char *quote = need_quote(arg);
		SAFE_BUF(snprintf, sizeof(buf), "%s%s%s%s", i > 0 ? " " : "", quote, arg, quote);
	}
	// Append a trailing space to ensure we get suggestions for missing args.
	SAFE_BUF(snprintf, sizeof(buf), " ");

	sug = get_suggestions(cmdlist, buf, &pos);
	if (sug == NULL && errno != 0) {
		errorf("exec_line_suggestions: %s", strerror(errno));
		goto err;
	}

	if (is_tty(stderr)) {
		fprintf(stderr, "%s* %.*s%s", YELLOW_SGR, pos, buf, RESET_SGR);
		fprintf(stderr, "%s%s%s\n", BOLD_RED_SGR, buf + pos, RESET_SGR);
		fprintf(stderr,
			"%s*%s %*s%s^%s\n",
			YELLOW_SGR,
			RESET_SGR,
			pos,
			"",
			BOLD_YELLOW_SGR,
			RESET_SGR);
	} else {
		fprintf(stderr, "* %s\n", buf);
		fprintf(stderr, "* %*s^\n", pos, "");
	}
	errorf("invalid arguments");
	if (sug != NULL && ec_strvec_len(sug) > 0) {
		fprintf(stderr, "expected: ");
		for (unsigned i = 0; i < ec_strvec_len(sug); i++) {
			if (i > 0)
				fprintf(stderr, ", ");
			fprintf(stderr, "%s", ec_strvec_val(sug, i));
		}
		fprintf(stderr, "\n");
	}

err:
	ec_strvec_free(sug);
}

static void
print_status(exec_status_t status, const struct ec_node *cmdlist, const struct ec_strvec *vec) {
	switch (status) {
	case EXEC_SUCCESS:
	case EXEC_CMD_EMPTY:
	case EXEC_CMD_EXIT:
	case EXEC_LEX_ERROR:
		break;
	case EXEC_CMD_INVALID_ARGS:
		print_suggestions(cmdlist, vec);
		break;
	case EXEC_CMD_FAILED:
		errorf("command failed: %s (%s)", strerrordesc_np(errno), strerrorname_np(errno));
		break;
	case EXEC_CB_UNDEFINED:
		errorf("no callback defined for command");
		break;
	case EXEC_OTHER_ERROR:
		errorf("fatal: %s", strerror(errno));
		break;
	}
}

static exec_status_t exec_strvec(
	struct gr_api_client *client,
	const struct ec_node *cmdlist,
	const struct ec_strvec *vec,
	bool trace
) {
	exec_status_t status = EXEC_OTHER_ERROR;
	struct ec_pnode *parsed = NULL;
	struct ec_strvec *args = NULL;
	cmd_cb_t cb;

	if (ec_strvec_len(vec) == 0) {
		status = EXEC_CMD_EMPTY;
		goto out;
	}

	// Try to expand all arguments to their non-ambiguous full name
	if ((args = ec_complete_strvec_expand(cmdlist, EC_COMP_FULL, vec)) == NULL)
		goto out;

	if (trace)
		trace_cmd(args);

	if ((parsed = ec_parse_strvec(cmdlist, args)) == NULL) {
		status = EXEC_OTHER_ERROR;
		goto out;
	}
	if (!ec_pnode_matches(parsed) || ec_pnode_len(parsed) != ec_strvec_len(args)) {
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
	print_status(status, cmdlist, args);
	ec_strvec_free(args);
	ec_pnode_free(parsed);
	return status;
}

exec_status_t exec_line(
	struct gr_api_client *client,
	const struct ec_node *cmdlist,
	const char *line,
	bool trace
) {
	exec_status_t status = EXEC_SUCCESS;
	struct ec_strvec *vec = NULL;

	errno = 0;
	if ((vec = ec_strvec_sh_lex_str(line, EC_STRVEC_STRICT, NULL)) == NULL) {
		if (errno == EBADMSG) {
			errorf("unterminated quote/escape");
			status = EXEC_LEX_ERROR;
		} else {
			errorf("ec_strvec_sh_lex_str: %s", strerror(errno));
			status = EXEC_OTHER_ERROR;
		}
		goto out;
	}
	if (ec_strvec_len(vec) == 0) {
		status = EXEC_CMD_EMPTY;
		goto out;
	}
	status = exec_strvec(client, cmdlist, vec, trace);
out:
	ec_strvec_free(vec);
	return status;
}

exec_status_t exec_args(
	struct gr_api_client *client,
	const struct ec_node *cmdlist,
	size_t argc,
	const char *const *argv,
	bool trace
) {
	exec_status_t status = EXEC_SUCCESS;
	struct ec_strvec *vec = NULL;

	if ((vec = ec_strvec_from_array(argv, argc)) == NULL) {
		errorf("ec_strvec_from_array: %s", strerror(errno));
		status = EXEC_OTHER_ERROR;
		goto out;
	}
	if (ec_strvec_len(vec) == 0) {
		status = EXEC_CMD_EMPTY;
		goto out;
	}
	status = exec_strvec(client, cmdlist, vec, trace);
out:
	ec_strvec_free(vec);
	return status;
}
