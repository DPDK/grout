// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_GRAPH
#define _BR_INFRA_GRAPH

#include <rte_common.h>
#include <rte_graph.h>

#include <sys/queue.h>

void *br_node_data_get(const char *graph, const char *node);

int br_node_data_set(const char *graph, const char *node, void *data);

rte_edge_t br_node_attach_parent(const char *parent, const char *node);

uint16_t drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t);

struct br_node_info {
	struct rte_node_register *node;
	void (*register_callback)(void);
	void (*unregister_callback)(void);
	STAILQ_ENTRY(br_node_info) next;
};

STAILQ_HEAD(node_infos, br_node_info);
extern struct node_infos node_infos;

#define BR_NODE_REGISTER(info)                                                                     \
	RTE_INIT(br_node_register_##info) {                                                        \
		STAILQ_INSERT_TAIL(&node_infos, &info, next);                                      \
	}

#define BR_DROP_REGISTER(node_name)                                                                \
	static struct rte_node_register drop_node_##node_name = {                                  \
		.name = #node_name,                                                                \
		.process = drop_packets,                                                           \
	};                                                                                         \
	static struct br_node_info drop_info_##node_name = {                                       \
		.node = &drop_node_##node_name,                                                    \
	};                                                                                         \
	RTE_INIT(br_drop_register_##node_name) {                                                   \
		STAILQ_INSERT_TAIL(&node_infos, &drop_info_##node_name, next);                     \
	}

#endif
