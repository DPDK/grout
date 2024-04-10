// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "exec.h"

#include <br_cli.h>
#include <br_net_types.h>

#include <ecoli.h>

#include <errno.h>

#define HELP_ATTR "help"

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

struct ec_node *with_callback(cmd_cb_t *cb, struct ec_node *node) {
	if (node == NULL)
		return NULL;
	struct ec_dict *attrs = ec_node_attrs(node);
	if (attrs == NULL || ec_dict_set(attrs, CALLBACK_ATTR, cb, NULL) < 0) {
		ec_node_free(node);
		node = NULL;
	}
	return node;
}

struct ec_node *cli_context(struct ec_node *root, const char *name, const char *help) {
	struct ec_node *ctx = NULL, *or_node = NULL;

	if (root == NULL || name == NULL || help == NULL) {
		errno = EINVAL;
		goto fail;
	}

	// if context is already present, return the OR node directly
	or_node = ec_node_find(root, name);
	if (or_node != NULL)
		return or_node;

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

const char *arg_str(const struct ec_pnode *p, const char *id) {
	const struct ec_pnode *n = ec_pnode_find(p, id);
	if (n == NULL) {
		errno = ENOENT;
		return NULL;
	}
	const struct ec_strvec *v = ec_pnode_get_strvec(n);
	if (v == NULL || ec_strvec_len(v) != 1) {
		errno = EIO;
		return NULL;
	}
	return ec_strvec_val(v, 0);
}

int arg_i64(const struct ec_pnode *p, const char *id, int64_t *val) {
	const struct ec_pnode *n = ec_pnode_find(p, id);
	if (n == NULL) {
		errno = ENOENT;
		goto err;
	}
	const struct ec_strvec *v = ec_pnode_get_strvec(n);
	if (v == NULL || ec_strvec_len(v) != 1) {
		errno = EFAULT;
		goto err;
	}
	const char *str = ec_strvec_val(v, 0);
	if (ec_node_int_getval(ec_pnode_get_node(n), str, val) < 0) {
		if (errno == 0)
			errno = EINVAL;
		goto err;
	}
	return 0;
err:
	return -1;
}

int arg_u64(const struct ec_pnode *p, const char *id, uint64_t *val) {
	const struct ec_pnode *n = ec_pnode_find(p, id);
	if (n == NULL) {
		errno = ENOENT;
		goto err;
	}
	const struct ec_strvec *v = ec_pnode_get_strvec(n);
	if (v == NULL || ec_strvec_len(v) != 1) {
		errno = EFAULT;
		goto err;
	}
	const char *str = ec_strvec_val(v, 0);
	if (ec_node_uint_getval(ec_pnode_get_node(n), str, val) < 0) {
		if (errno == 0)
			errno = EINVAL;
		goto err;
	}
	return 0;
err:
	return -1;
}

int arg_eth_addr(const struct ec_pnode *p, const char *id, struct eth_addr *val) {
	const struct ec_pnode *n = ec_pnode_find(p, id);
	if (n == NULL) {
		errno = ENOENT;
		goto err;
	}
	const struct ec_strvec *v = ec_pnode_get_strvec(n);
	if (v == NULL || ec_strvec_len(v) != 1) {
		errno = EFAULT;
		goto err;
	}
	const char *str = ec_strvec_val(v, 0);

	if (br_eth_addr_parse(str, val) < 0) {
		errno = EINVAL;
		goto err;
	}
	return 0;
err:
	return -1;
}
