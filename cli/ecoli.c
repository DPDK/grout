// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "exec.h"

#include <br_cli.h>

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

const char *arg_str(const struct ec_pnode *p, const char *id) {
	const struct ec_pnode *n = ec_pnode_find(p, id);
	if (n == NULL)
		goto err;
	const struct ec_strvec *v = ec_pnode_get_strvec(n);
	if (v == NULL || ec_strvec_len(v) != 1)
		goto err;
	return ec_strvec_val(v, 0);
err:
	errno = EINVAL;
	return NULL;
}

int arg_int(const struct ec_pnode *p, const char *id, int64_t *val) {
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

int arg_uint(const struct ec_pnode *p, const char *id, uint64_t *val) {
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
