// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_errno.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <sys/queue.h>

typedef int (*cli_ctx_init_t)(struct ec_node *root);

struct cli_context {
	const char *name;
	cli_ctx_init_t init;
	STAILQ_ENTRY(cli_context) next;
};

void cli_context_register(struct cli_context *);

void errorf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

typedef enum {
	CMD_SUCCESS,
	CMD_ERROR,
	CMD_EXIT,
} cmd_status_t;

typedef cmd_status_t (*cmd_cb_t)(struct gr_api_client *, const struct ec_pnode *);

struct ec_node *with_help(const char *help, struct ec_node *node);

struct ec_node *with_callback(cmd_cb_t cb, struct ec_node *node);

struct ctx_arg {
	const char *name;
	const char *help;
};

struct ec_node *__cli_context(struct ec_node *root, const struct ctx_arg *arg, ...);

const char *arg_str(const struct ec_pnode *p, const char *id);
int arg_i64(const struct ec_pnode *p, const char *id, int64_t *);
int arg_u64(const struct ec_pnode *p, const char *id, uint64_t *);
int arg_eth_addr(const struct ec_pnode *p, const char *id, struct rte_ether_addr *);
int arg_ip(const struct ec_pnode *p, const char *id, void *addr, int af);
int arg_ip4(const struct ec_pnode *p, const char *id, ip4_addr_t *addr);
int arg_ip6(const struct ec_pnode *p, const char *id, struct rte_ipv6_addr *addr);
int arg_ip_net(const struct ec_pnode *p, const char *id, void *net, bool zero_mask, int af);
int arg_ip4_net(const struct ec_pnode *p, const char *id, struct ip4_net *net, bool zero_mask);
int arg_ip6_net(const struct ec_pnode *p, const char *id, struct ip6_net *net, bool zero_mask);

static inline int arg_u8(const struct ec_pnode *p, const char *id, uint8_t *val) {
	uint64_t v;
	int ret = arg_u64(p, id, &v);
	if (ret == 0)
		*val = v;
	return ret;
}

static inline int arg_u16(const struct ec_pnode *p, const char *id, uint16_t *val) {
	uint64_t v;
	int ret = arg_u64(p, id, &v);
	if (ret == 0)
		*val = v;
	return ret;
}

static inline int arg_u32(const struct ec_pnode *p, const char *id, uint32_t *val) {
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

typedef int (*ec_node_dyn_comp_t)(
	struct gr_api_client *,
	const struct ec_node *,
	struct ec_comp *,
	const char *arg,
	void *cb_arg
);

struct ec_node *ec_node_dyn(const char *id, ec_node_dyn_comp_t cb, void *cb_arg);

#define CLIENT_ATTR "gr_api_client"
#define HELP_ATTR "help"
#define SOCK_PATH_ID "gr_api_sock_path"
