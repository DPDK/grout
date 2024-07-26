// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_CLI
#define _GR_CLI

#include <gr_api.h>
#include <gr_net_types.h>

#include <ecoli.h>
#include <rte_ether.h>

#include <sys/queue.h>

typedef int(gr_cli_ctx_init_t)(struct ec_node *root);

struct gr_cli_context {
	const char *name;
	gr_cli_ctx_init_t *init;
	STAILQ_ENTRY(gr_cli_context) entries;
};

void register_context(struct gr_cli_context *);

void errorf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

typedef enum {
	CMD_SUCCESS,
	CMD_ERROR,
	CMD_EXIT,
} cmd_status_t;

typedef cmd_status_t(cmd_cb_t)(const struct gr_api_client *, const struct ec_pnode *);

struct ec_node *with_help(const char *help, struct ec_node *node);

struct ec_node *with_callback(cmd_cb_t *cb, struct ec_node *node);

struct ctx_arg {
	const char *name;
	const char *help;
};

struct ec_node *__cli_context(struct ec_node *root, const struct ctx_arg *arg, ...);

const char *arg_str(const struct ec_pnode *p, const char *id);
int arg_i64(const struct ec_pnode *p, const char *id, int64_t *);
int arg_u64(const struct ec_pnode *p, const char *id, uint64_t *);
int arg_eth_addr(const struct ec_pnode *p, const char *id, struct rte_ether_addr *);

static inline int arg_u16(const struct ec_pnode *p, const char *id, uint16_t *val) {
	uint64_t v;
	int ret = arg_u64(p, id, &v);
	if (ret == 0)
		*val = v;
	return ret;
}

#define CTX_END                                                                                    \
	&(const struct ctx_arg) {                                                                  \
		.name = NULL                                                                       \
	}
#define CTX_ARG(n, h)                                                                              \
	&(const struct ctx_arg) {                                                                  \
		.name = n, .help = h                                                               \
	}
#define CLI_CONTEXT(root, ...) __cli_context(root, __VA_ARGS__, CTX_END)

#define CLI_COMMAND(ctx, cmd, cb, help, ...)                                                       \
	ec_node_or_add(                                                                            \
		ctx,                                                                               \
		with_callback(                                                                     \
			cb, with_help(help, EC_NODE_CMD(cmd, cmd __VA_OPT__(, ) __VA_ARGS__))      \
		)                                                                                  \
	)

#define CTX_ADD CTX_ARG("add", "Create objects in the configuration.")
#define CTX_SET CTX_ARG("set", "Modify existing objects in the configuration.")
#define CTX_DEL CTX_ARG("del", "Delete objects from the configuration.")
#define CTX_SHOW CTX_ARG("show", "Display information about the configuration.")
#define CTX_CLEAR CTX_ARG("clear", "Clear counters or temporary entries.")

typedef int (*ec_node_dyn_comp_t)(
	const struct gr_api_client *,
	const struct ec_node *,
	struct ec_comp *,
	const char *arg,
	void *cb_arg
);

struct ec_node *ec_node_dyn(const char *id, ec_node_dyn_comp_t cb, void *cb_arg);

#define CLIENT_ATTR "gr_api_client"
#define SOCK_PATH_ID "gr_api_sock_path"

#endif
