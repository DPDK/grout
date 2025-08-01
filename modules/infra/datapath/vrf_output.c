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
	INVALID_IFACE,
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
vrf_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_input_mbuf_data *eth_data;
	struct iface_stats *stats;
	struct iface *vrf_iface;
	struct rte_mbuf *m;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];

		if (m->packet_type & RTE_PTYPE_L3_IPV4) {
			edge = IP_INPUT;
			vrf_iface = iface_from_id(ip_output_mbuf_data(m)->nh->iface_id);
		} else {
			edge = IP6_INPUT;
			vrf_iface = iface_from_id(ip6_output_mbuf_data(m)->nh->iface_id);
		}
		if (vrf_iface == NULL || vrf_iface->type != GR_IFACE_TYPE_VRF) {
			edge = INVALID_IFACE; // should not happens
			goto next;
		}

		eth_data = eth_input_mbuf_data(m);
		eth_data->iface = vrf_iface;
		eth_data->domain = ETH_DOMAIN_LOCAL;

		stats = iface_get_stats(vrf_iface->id);
		stats->rx_packets[rte_lcore_id()] += 1;
		stats->rx_bytes[rte_lcore_id()] += rte_pktmbuf_pkt_len(m);
next:
		if (gr_mbuf_is_traced(m)
		    || (vrf_iface && vrf_iface->flags & GR_IFACE_F_PACKET_TRACE)) {
			struct trace_vrf_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->vrf_id = vrf_iface ? vrf_iface->id : UINT16_MAX;
		}

		rte_node_enqueue_x1(graph, node, edge, m);
	}
	return nb_objs;
}

static void vrf_output_register(void) {
	ip_output_register_interface_type(GR_IFACE_TYPE_VRF, "vrf_output");
	ip6_output_register_interface_type(GR_IFACE_TYPE_VRF, "vrf_output");
}

static struct rte_node_register vrf_output_node = {
	.name = "vrf_output",
	.process = vrf_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_INPUT] = "ip_input",
		[IP6_INPUT] = "ip6_input",
		[INVALID_IFACE] = "vrf_iface_invalid",
	},
};

static struct gr_node_info info = {
	.node = &vrf_output_node,
	.register_callback = vrf_output_register,
	.trace_format = trace_vrf_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(vrf_iface_invalid);
