// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_DATAPATH
#define _BR_INFRA_DATAPATH

#include <br_log.h>

#include <rte_build_config.h>
#include <rte_errno.h>
#include <rte_graph_worker.h>
#include <rte_hash.h>

#include <stdint.h>

void *br_datapath_loop(void *priv);

struct node_ctx_key {
	char key[RTE_NODE_NAMESIZE];
};

#define NODE_CTX_DATA_HASH_NAME "ctx_data"

struct rx_node_ctx {
	uint16_t port_id;
	uint16_t rxq_id;
	uint16_t burst;
};

struct tx_node_ctx {
	uint16_t port_id;
	uint16_t txq_id;
};

#define EDGE_DROP 0
#define EDGE_DEFAULT 1

struct port_edge_map {
	rte_edge_t edges[RTE_MAX_ETHPORTS];
};

static inline void copy_node_key(struct node_ctx_key *key, const char *name) {
	memset(key, 0, sizeof(*key));
	memccpy(key->key, name, 0, sizeof(key->key));
}

static inline int get_ctx_data(struct rte_node *node, void **data) {
	struct rte_hash *hash = rte_hash_find_existing(NODE_CTX_DATA_HASH_NAME);
	struct node_ctx_key key;

	if (hash == NULL)
		return -rte_errno;

	copy_node_key(&key, node->name);

	if (rte_hash_lookup_data(hash, &key, data) < 0)
		return -rte_errno;

	return 0;
}

#endif
