// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "exec.h"

#include <gr_cli.h>

#include <ecoli.h>

#include <errno.h>
#include <stdarg.h>

struct ec_node *with_help(const char *help, struct ec_node *node) {
	if (node == NULL)
		return NULL;
	struct ec_dict *attrs = ec_node_attrs(node);
	if (attrs == NULL || ec_dict_set(attrs, HELP_ATTR, (void *)help, NULL) < 0) {
		ec_node_free(node);
		node = NULL;
	}
	return node;
}

struct ec_node *with_callback(cmd_cb_t cb, struct ec_node *node) {
	if (node == NULL)
		return NULL;
	struct ec_dict *attrs = ec_node_attrs(node);
	if (attrs == NULL || ec_dict_set(attrs, CALLBACK_ATTR, cb, NULL) < 0) {
		ec_node_free(node);
		node = NULL;
	}
	return node;
}

static struct ec_node *get_or_create(struct ec_node *root, const char *name, const char *help) {
	struct ec_node *ctx = NULL, *or_node = NULL;

	if (root == NULL || name == NULL || help == NULL) {
		errno = EINVAL;
		goto fail;
	}

	for (unsigned i = 0; i < ec_node_get_children_count(root); i++) {
		struct ec_node *seq_node;
		unsigned refs;
		if (ec_node_get_child(root, i, &seq_node, &refs) < 0)
			continue;
		if (strcmp(ec_node_type(seq_node)->name, "seq") != 0)
			continue;
		if (ec_node_get_children_count(seq_node) != 2)
			continue;
		if (ec_node_get_child(seq_node, 1, &or_node, &refs) < 0)
			continue;
		if (strcmp(ec_node_type(or_node)->name, "or") != 0)
			continue;
		if (strcmp(ec_node_id(or_node), name) == 0) {
			// if context is already present, return the OR node directly
			return or_node;
		}
	}

	// else, create the context node
	if ((or_node = ec_node("or", name)) == NULL)
		goto fail;
	ctx = EC_NODE_SEQ(EC_NO_ID, with_help(help, ec_node_str(EC_NO_ID, name)), or_node);
	if (ctx == NULL)
		goto fail;
	if (ec_node_or_add(root, ctx) < 0)
		goto fail;

	return or_node;
fail:
	ec_node_free(ctx);
	return NULL;
}

struct ec_node *__cli_context(struct ec_node *root, const struct ctx_arg *arg, ...) {
	struct ec_node *ctx;
	va_list ap;

	ctx = get_or_create(root, arg->name, arg->help);
	if (ctx == NULL)
		goto end;

	va_start(ap, arg);
	for (arg = va_arg(ap, const struct ctx_arg *); arg->name != NULL;
	     arg = va_arg(ap, const struct ctx_arg *)) {
		ctx = get_or_create(ctx, arg->name, arg->help);
		if (ctx == NULL)
			goto end;
	}
end:
	va_end(ap);
	return ctx;
}

const char *arg_str(const struct ec_pnode *p, const char *id) {
	const struct ec_pnode *n = ec_pnode_find(p, id);
	if (n == NULL)
		return errno_set_null(ENOENT);

	const struct ec_strvec *v = ec_pnode_get_strvec(n);
	if (v == NULL || ec_strvec_len(v) != 1)
		return errno_set_null(EIO);

	return ec_strvec_val(v, 0);
}

int arg_i64(const struct ec_pnode *p, const char *id, int64_t *val) {
	const struct ec_pnode *n = ec_pnode_find(p, id);
	if (n == NULL)
		return errno_set(ENOENT);

	const struct ec_strvec *v = ec_pnode_get_strvec(n);
	if (v == NULL || ec_strvec_len(v) != 1)
		return errno_set(EFAULT);

	const char *str = ec_strvec_val(v, 0);
	if (ec_node_int_getval(ec_pnode_get_node(n), str, val) < 0)
		return errno_set(EINVAL);

	return 0;
}

int arg_u64(const struct ec_pnode *p, const char *id, uint64_t *val) {
	const struct ec_pnode *n = ec_pnode_find(p, id);
	if (n == NULL)
		return errno_set(ENOENT);

	const struct ec_strvec *v = ec_pnode_get_strvec(n);
	if (v == NULL || ec_strvec_len(v) != 1)
		return errno_set(EFAULT);

	const char *str = ec_strvec_val(v, 0);
	if (ec_node_uint_getval(ec_pnode_get_node(n), str, val) < 0)
		return errno_set(EINVAL);

	return 0;
}

static int eth_addr_parse(const char *s, struct rte_ether_addr *mac) {
	if (s == NULL)
		goto err;
	int ret = sscanf(
		s,
		"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%*c",
		&mac->addr_bytes[0],
		&mac->addr_bytes[1],
		&mac->addr_bytes[2],
		&mac->addr_bytes[3],
		&mac->addr_bytes[4],
		&mac->addr_bytes[5]
	);
	if (ret != 6)
		goto err;
	return 0;
err:
	errno = EINVAL;
	return -1;
}

int arg_eth_addr(const struct ec_pnode *p, const char *id, struct rte_ether_addr *val) {
	const struct ec_pnode *n = ec_pnode_find(p, id);
	if (n == NULL)
		return errno_set(ENOENT);

	const struct ec_strvec *v = ec_pnode_get_strvec(n);
	if (v == NULL || ec_strvec_len(v) != 1)
		return errno_set(EFAULT);

	const char *str = ec_strvec_val(v, 0);
	if (eth_addr_parse(str, val) < 0)
		return errno_set(EINVAL);

	return 0;
}

int arg_ip(const struct ec_pnode *p, const char *id, void *addr, int family) {
	const char *str = arg_str(p, id);
	if (str == NULL)
		return -errno;

	if (inet_pton(family, str, addr) != 1)
		return errno_set(EINVAL);

	return 0;
}

int arg_ip4(const struct ec_pnode *p, const char *id, ip4_addr_t *addr) {
	return arg_ip(p, id, addr, AF_INET);
}

int arg_ip6(const struct ec_pnode *p, const char *id, struct rte_ipv6_addr *addr) {
	return arg_ip(p, id, addr, AF_INET6);
}

int arg_ip_net(const struct ec_pnode *p, const char *id, void *net, bool zero_mask, int family) {
	const char *str = arg_str(p, id);
	if (str == NULL)
		return -errno;

	switch (family) {
	case AF_INET:
		return ip4_net_parse(str, net, zero_mask);
	case AF_INET6:
		return ip6_net_parse(str, net, zero_mask);
	default:
		return errno_set(EINVAL);
	}
}

int arg_ip4_net(const struct ec_pnode *p, const char *id, struct ip4_net *net, bool zero_mask) {
	return arg_ip_net(p, id, net, zero_mask, AF_INET);
}

int arg_ip6_net(const struct ec_pnode *p, const char *id, struct ip6_net *net, bool zero_mask) {
	return arg_ip_net(p, id, net, zero_mask, AF_INET6);
}
