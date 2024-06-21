// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>

#include <rte_graph_worker.h>
#include <rte_icmp.h>
#include <rte_ip.h>

#include <netinet/in.h>

enum {
	OUTPUT = 0,
	EDGE_COUNT,
};

static uint16_t
icmp_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip_local_mbuf_data *local_data;
	struct rte_icmp_hdr *icmp;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		local_data = ip_local_mbuf_data(mbuf);

		icmp = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr *);
		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = ~rte_raw_cksum(icmp, local_data->len);

		ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));
		ip_set_fields(ip, local_data);
		ip_output_mbuf_data(mbuf)->nh = ip4_route_lookup(
			local_data->vrf_id, local_data->dst
		);
	}

	rte_node_enqueue(graph, node, OUTPUT, objs, nb_objs);

	return nb_objs;
}

static struct rte_node_register icmp_output_node = {
	.name = "icmp_output",

	.process = icmp_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "ip_output",
	},
};

static struct gr_node_info icmp_output_info = {
	.node = &icmp_output_node,
};

GR_NODE_REGISTER(icmp_output_info);
