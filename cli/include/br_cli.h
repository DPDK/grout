// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CLI
#define _BR_CLI

#include <br_client.h>
#include <br_net_types.h>

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

struct ec_node *cli_context(struct ec_node *root, const char *name, const char *help);

const char *arg_str(const struct ec_pnode *p, const char *id);
int arg_int(const struct ec_pnode *p, const char *id, int64_t *);
int arg_uint(const struct ec_pnode *p, const char *id, uint64_t *);
int arg_eth_addr(const struct ec_pnode *p, const char *id, struct eth_addr *);

#define CLI_COMMAND(ctx, cmd, cb, help, ...)                                                       \
	ec_node_or_add(                                                                            \
		ctx,                                                                               \
		with_callback(                                                                     \
			cb, with_help(help, EC_NODE_CMD(cmd, cmd __VA_OPT__(, ) __VA_ARGS__))      \
		)                                                                                  \
	)

#endif
