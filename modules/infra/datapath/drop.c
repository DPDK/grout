// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include <rte_graph.h>
#include <rte_mbuf.h>

static uint16_t
drop_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	(void)node;
	(void)graph;

	rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, nb_objs);

	return nb_objs;
}

static struct rte_node_register drop_node = {
	.process = drop_process,
	.name = "br_drop",
};

RTE_NODE_REGISTER(drop_node)
