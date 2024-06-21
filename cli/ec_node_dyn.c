// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "gr_cli.h"

#include <gr_api.h>

#include <ecoli.h>

#include <assert.h>
#include <errno.h>

EC_LOG_TYPE_REGISTER(node_dyn);

struct ec_node_dyn {
	ec_node_dyn_comp_t cb;
	void *cb_arg;
};

static int ec_node_dyn_parse(
	const struct ec_node *node,
	struct ec_pnode *pstate,
	const struct ec_strvec *strvec
) {
	(void)node;
	(void)pstate;

	if (ec_strvec_len(strvec) == 0)
		return EC_PARSE_NOMATCH;

	return 1;
}

static void disconnect_client(void *ptr) {
	gr_api_client_disconnect(ptr);
}

static struct gr_api_client *connect_client(struct ec_comp *comp) {
	const struct ec_pnode *pstate = ec_comp_get_cur_pstate(comp);
	const char *sock_path = NULL;
	struct gr_api_client *client;

	// find the root of the parsed tree
	while (ec_pnode_get_parent(pstate) != NULL)
		pstate = ec_pnode_get_parent(pstate);

	// find a parsed -s or --sock-path argument value
	pstate = ec_pnode_find(pstate, SOCK_PATH_ID);
	if (pstate != NULL) {
		const struct ec_strvec *vec = ec_pnode_get_strvec(pstate);
		if (ec_strvec_len(vec) == 1)
			sock_path = ec_strvec_val(vec, 0);
	}
	if (sock_path == NULL)
		sock_path = GR_DEFAULT_SOCK_PATH; // not specified, use default

	client = gr_api_client_connect(sock_path);
	if (client != NULL) {
		// attach the connected client to the complete tree so that it is
		// automatically disconnected when the tree is freed.
		ec_dict_set(ec_comp_get_attrs(comp), CLIENT_ATTR, client, disconnect_client);
	}

	return client;
}

static const struct gr_api_client *get_client(struct ec_comp *comp) {
	struct ec_pnode *pstate = ec_comp_get_cur_pstate(comp);
	const struct gr_api_client *client = NULL;

	while (client == NULL && pstate != NULL) {
		const struct ec_node *node = ec_pnode_get_node(pstate);
		if (node == NULL)
			break;
		client = ec_dict_get(ec_node_attrs(node), CLIENT_ATTR);
		pstate = ec_pnode_get_parent(pstate);
	}

	return client;
}

static int ec_node_dyn_complete(
	const struct ec_node *node,
	struct ec_comp *comp,
	const struct ec_strvec *strvec
) {
	const struct ec_node_dyn *priv = ec_node_priv(node);
	const struct gr_api_client *client;

	assert(priv->cb != NULL);

	if (ec_strvec_len(strvec) != 1)
		return 0;

	client = get_client(comp);
	if (client == NULL)
		client = connect_client(comp);
	if (client == NULL)
		return -1;

	return priv->cb(client, node, comp, ec_strvec_val(strvec, 0), priv->cb_arg);
}

static char *ec_node_dyn_desc(const struct ec_node *node) {
	const char *id = ec_node_id(node);
	char *desc = NULL;

	if (strcmp(id, EC_NO_ID) == 0)
		id = "any";
	if (asprintf(&desc, "<%s>", id) < 0)
		return NULL;

	return desc;
}

static struct ec_node_type ec_node_dyn_type = {
	.name = "dyn",
	.parse = ec_node_dyn_parse,
	.complete = ec_node_dyn_complete,
	.desc = ec_node_dyn_desc,
	.size = sizeof(struct ec_node_dyn),
};

struct ec_node *ec_node_dyn(const char *id, ec_node_dyn_comp_t cb, void *cb_arg) {
	struct ec_node *node;

	if (cb == NULL) {
		errno = EINVAL;
		return NULL;
	}

	node = ec_node_from_type(&ec_node_dyn_type, id);
	if (node != NULL) {
		struct ec_node_dyn *priv = ec_node_priv(node);
		priv->cb = cb;
		priv->cb_arg = cb_arg;
	}

	return node;
}

EC_NODE_TYPE_REGISTER(ec_node_dyn_type);
