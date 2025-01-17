// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_fib4.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>

#include <rte_graph_worker.h>
#include <rte_icmp.h>
#include <rte_ip.h>

#include <netinet/in.h>

enum {
	OUTPUT = 0,
	NO_HEADROOM,
	NO_ROUTE,
	EDGE_COUNT,
};

static uint16_t
icmp_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip_local_mbuf_data *local_data;
	struct ip_output_mbuf_data *o;
	struct rte_icmp_hdr *icmp;
	const struct nexthop *nh;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		local_data = ip_local_mbuf_data(mbuf);

		icmp = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr *);
		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = ~rte_raw_cksum(icmp, local_data->len);

		ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));
		if (unlikely(ip == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		ip_set_fields(ip, local_data);
		if ((nh = fib4_lookup(local_data->vrf_id, local_data->dst)) == NULL) {
			// Do not let packets go to ip_output from icmp_output
			// with no available route to avoid loops of destination
			// unreachable errors.
			edge = NO_ROUTE;
			goto next;
		}
		o = ip_output_mbuf_data(mbuf);
		o->nh = nh;
		o->iface = NULL;
		edge = OUTPUT;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register icmp_output_node = {
	.name = "icmp_output",

	.process = icmp_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "ip_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_ROUTE] = "icmp_output_no_route",
	},
};

static struct gr_node_info icmp_output_info = {
	.node = &icmp_output_node,
};

GR_NODE_REGISTER(icmp_output_info);

GR_DROP_REGISTER(icmp_output_no_route);
