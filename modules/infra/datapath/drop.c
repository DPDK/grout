// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_graph.h>

#include <rte_graph.h>
#include <rte_mbuf.h>

uint16_t br_node_drop_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	(void)node;
	(void)graph;

	rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, nb_objs);

	return nb_objs;
}
