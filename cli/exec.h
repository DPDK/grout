// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CLI_EXEC
#define _BR_CLI_EXEC

#include <br_api.h>

#include <ecoli.h>

struct ec_node *init_commands(void);

typedef enum {
	EXEC_SUCCESS,
	EXEC_LEX_ERROR, // unterminated quote/escape, only for exec_line
	EXEC_CMD_EMPTY, // no arguments after lexing
	EXEC_CMD_EXIT, // callback asked to exit
	EXEC_CMD_INVALID_ARGS, // command not recognized
	EXEC_CMD_FAILED, // command callback returned an error
	EXEC_CB_UNDEFINED, // no callback registered, internal error
	EXEC_OTHER_ERROR, // other internal error
} exec_status_t;

#define CALLBACK_ATTR "callback"

exec_status_t exec_line(const struct br_api_client *, const struct ec_node *, const char *line);

exec_status_t exec_args(
	const struct br_api_client *,
	const struct ec_node *,
	size_t argc,
	const char *const *argv
);

#endif
