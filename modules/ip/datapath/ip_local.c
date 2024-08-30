// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>

#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#define UNKNOWN_PROTO 0
static rte_edge_t edges[256] = {UNKNOWN_PROTO};

void ip_input_local_add_proto(uint8_t proto, const char *next_node) {
	LOG(DEBUG, "ip_input_local: proto=%hhu -> %s", proto, next_node);
	if (edges[proto] != UNKNOWN_PROTO)
		ABORT("next node already registered for proto=%hhu", proto);
	edges[proto] = gr_node_attach_parent("ip_input_local", next_node);
}

static uint16_t ip_input_local_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		edge = edges[ip->next_proto_id];
		if (edge != UNKNOWN_PROTO) {
			const struct iface *iface = ip_output_mbuf_data(mbuf)->input_iface;
			struct ip_local_mbuf_data *data = ip_local_mbuf_data(mbuf);
			data->src = ip->src_addr;
			data->dst = ip->dst_addr;
			data->len = rte_be_to_cpu_16(ip->total_length) - rte_ipv4_hdr_len(ip);
			data->vrf_id = iface->vrf_id;
			data->proto = ip->next_proto_id;
			rte_pktmbuf_adj(mbuf, sizeof(*ip));
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register input_node = {
	.name = "ip_input_local",
	.process = ip_input_local_process,
	.nb_edges = 1,
	.next_nodes = {
		[UNKNOWN_PROTO] = "ip_input_local_unknown_proto",
	},
};

static struct gr_node_info info = {
	.node = &input_node,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip_input_local_unknown_proto);
