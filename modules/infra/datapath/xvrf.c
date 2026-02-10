// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include <gr_datapath.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

enum {
	IP_INPUT,
	IP6_INPUT,
	EDGE_COUNT,
};

struct trace_vrf_data {
	uint16_t vrf_id;
};

static int trace_vrf_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_vrf_data *t = data;
	return snprintf(buf, len, "vrf=%u", t->vrf_id);
}

static uint16_t
xvrf_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_input_mbuf_data *eth_data;
	struct iface_stats *stats;
	struct rte_mbuf *m;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		if (m->packet_type & RTE_PTYPE_L3_IPV4)
			edge = IP_INPUT;
		else
			edge = IP6_INPUT;

		eth_data = eth_input_mbuf_data(m);
		eth_data->domain = ETH_DOMAIN_LOCAL;

		// XXX: increment tx stats on source VRF
		stats = iface_get_stats(rte_lcore_id(), eth_data->iface->id);
		stats->rx_packets += 1;
		stats->rx_bytes += rte_pktmbuf_pkt_len(m);

		if (gr_mbuf_is_traced(m) || (eth_data->iface->flags & GR_IFACE_F_PACKET_TRACE)) {
			struct trace_vrf_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->vrf_id = eth_data->iface->vrf_id;
		}

		rte_node_enqueue_x1(graph, node, edge, m);
	}
	return nb_objs;
}

static void xvrf_register(void) {
	ip_output_register_interface_type(GR_IFACE_TYPE_VRF, "xvrf");
	ip6_output_register_interface_type(GR_IFACE_TYPE_VRF, "xvrf");
}

static struct rte_node_register xvrf_node = {
	.name = "xvrf",
	.process = xvrf_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_INPUT] = "ip_input",
		[IP6_INPUT] = "ip6_input",
	},
};

static struct gr_node_info info = {
	.node = &xvrf_node,
	.type = GR_NODE_T_L3,
	.register_callback = xvrf_register,
	.trace_format = trace_vrf_format,
};

GR_NODE_REGISTER(info);
