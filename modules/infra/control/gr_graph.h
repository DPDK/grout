// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_GRAPH
#define _GR_INFRA_GRAPH

#include <gr_trace.h>

#include <rte_common.h>
#include <rte_graph.h>

#include <sys/queue.h>

void *gr_node_data_get(const char *graph, const char *node);

int gr_node_data_set(const char *graph, const char *node, void *data);

rte_edge_t gr_node_attach_parent(const char *parent, const char *node);

uint16_t drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t);

typedef void (*gr_node_register_cb_t)(void);

struct gr_node_info {
	struct rte_node_register *node;
	gr_node_register_cb_t register_callback;
	gr_node_register_cb_t unregister_callback;
	gr_trace_format_cb_t trace_format;
	STAILQ_ENTRY(gr_node_info) next;
};

const struct gr_node_info *gr_node_info_get(rte_node_t node_id);

STAILQ_HEAD(node_infos, gr_node_info);
extern struct node_infos node_infos;

#define GR_NODE_REGISTER(info)                                                                     \
	RTE_INIT(gr_node_register_##info) {                                                        \
		STAILQ_INSERT_TAIL(&node_infos, &info, next);                                      \
	}

#define GR_DROP_REGISTER(node_name)                                                                \
	static struct rte_node_register drop_node_##node_name = {                                  \
		.name = #node_name,                                                                \
		.process = drop_packets,                                                           \
	};                                                                                         \
	static struct gr_node_info drop_info_##node_name = {                                       \
		.node = &drop_node_##node_name,                                                    \
	};                                                                                         \
	RTE_INIT(gr_drop_register_##node_name) {                                                   \
		STAILQ_INSERT_TAIL(&node_infos, &drop_info_##node_name, next);                     \
	}

#endif
