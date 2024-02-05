// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_GRAPH
#define _BR_INFRA_GRAPH

#include <rte_common.h>
#include <rte_graph.h>

#include <sys/queue.h>

#define NODE_CTX_PTR(type, var, node)                                                              \
	type var;                                                                                  \
	_Static_assert(sizeof(*var) <= sizeof(node->ctx));                                         \
	var = (type)node->ctx

int br_node_data_get(const char *graph, const char *node, void **data);

int br_node_data_set(const char *graph, const char *node, void *data);

rte_edge_t br_node_attach_parent(const char *parent, const char *node);

struct br_node_info {
	struct rte_node_register *node;
	void (*register_callback)(void);
	LIST_ENTRY(br_node_info) next;
};

LIST_HEAD(node_infos, br_node_info);
extern struct node_infos node_infos;

#define BR_NODE_REGISTER(info)                                                                     \
	RTE_INIT(br_node_register_##info) {                                                        \
		LIST_INSERT_HEAD(&node_infos, &info, next);                                        \
	}

#endif
