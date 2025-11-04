// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_graph.h>
#include <gr_ip6_datapath.h>
#include <gr_mbuf.h>
#include <gr_trace.h>
#include <gr_vec.h>

#include <rte_fib.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum edges {
	OUTPUT = 0,
	NO_NEXTHOP,
	EDGE_COUNT,
};

static uint16_t ip6_loadbalance_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct ip6_output_mbuf_data *d;
	struct nexthop_info_group *g;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		d = ip6_output_mbuf_data(mbuf);
		g = (struct nexthop_info_group *)d->nh->info;
		edge = OUTPUT;
		// TODO: increment xstat on ! mbuf->ol_flags & RTE_MBUF_F_RX_RSS_HASH
		d->nh = nexthop_group_get_nh(g, mbuf->hash.rss);
		if (unlikely(d->nh == NULL)) {
			edge = NO_NEXTHOP;
			goto next;
		}
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);

		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void loadbalance_register(void) {
	ip6_output_register_nexthop_type(GR_NH_T_GROUP, "ip6_loadbalance");
}

static struct rte_node_register ip6_lb_node = {
	.name = "ip6_loadbalance",
	.process = ip6_loadbalance_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "ip6_output",
		[NO_NEXTHOP] = "ip6_lb_no_nexthop",
	},
};

static struct gr_node_info info_loadbalance = {
	.node = &ip6_lb_node,
	.register_callback = loadbalance_register,
};

GR_NODE_REGISTER(info_loadbalance);
GR_DROP_REGISTER(ip6_lb_no_nexthop);
