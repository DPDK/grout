// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CLI
#define _BR_CLI

#include <br_client.h>

#include <ecoli.h>

#include <sys/queue.h>

typedef int(br_cli_ctx_init_t)(struct ec_node *root);

struct br_cli_context {
	const char *name;
	br_cli_ctx_init_t *init;
	LIST_ENTRY(br_cli_context) entries;
};

void register_context(struct br_cli_context *);

void errorf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

typedef enum {
	CMD_SUCCESS,
	CMD_ERROR,
	CMD_EXIT,
} cmd_status_t;

typedef cmd_status_t(cmd_cb_t)(const struct br_client *, const struct ec_pnode *);

struct ec_node *with_help(const char *help, struct ec_node *node);

struct ec_node *with_callback(cmd_cb_t *cb, struct ec_node *node);

const char *arg_str(const struct ec_pnode *p, const char *id);

#define CLI_COMMAND_CONTEXT(name, help, ...)                                                       \
	EC_NODE_SEQ(                                                                               \
		EC_NO_ID,                                                                          \
		with_help(help, ec_node_str(name, name)),                                          \
		EC_NODE_OR(EC_NO_ID, __VA_ARGS__)                                                  \
	)

#define CLI_COMMAND(cmd, cb, help, ...)                                                            \
	with_callback(cb, with_help(help, EC_NODE_CMD(cmd, cmd __VA_OPT__(, ) __VA_ARGS__)))

#endif
