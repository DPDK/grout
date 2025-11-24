// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_trace.h>

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

		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);

		edge = edges[ip->next_proto_id];
		if (edge != UNKNOWN_PROTO) {
			const struct iface *iface = ip_output_mbuf_data(mbuf)->iface;
			struct ip_local_mbuf_data *data = ip_local_mbuf_data(mbuf);
			data->src = ip->src_addr;
			data->dst = ip->dst_addr;
			data->len = rte_be_to_cpu_16(ip->total_length) - rte_ipv4_hdr_len(ip);
			data->vrf_id = iface->vrf_id;
			data->proto = ip->next_proto_id;
			data->ttl = ip->time_to_live;
			rte_pktmbuf_adj(mbuf, rte_ipv4_hdr_len(ip));
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
	.type = GR_NODE_T_L3,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip_input_local_unknown_proto);
