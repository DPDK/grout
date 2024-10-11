// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ipip_priv.h"

#include <gr_datapath.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_ipip.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>

#include <netinet/in.h>

enum {
	IP_OUTPUT = 0,
	NO_TUNNEL,
	NO_HEADROOM,
	EDGE_COUNT,
};

static uint16_t
ipip_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip_output_mbuf_data *ip_data;
	const struct iface_info_ipip *ipip;
	struct ip_local_mbuf_data tunnel;
	const struct rte_ipv4_hdr *inner;
	struct rte_ipv4_hdr *outer;
	const struct iface *iface;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		// Resolve the IPIP interface from the nexthop provided by ip_output.
		ip_data = ip_output_mbuf_data(mbuf);
		iface = iface_from_id(ip_data->nh->iface_id);
		if (iface == NULL || iface->type_id != GR_IFACE_TYPE_IPIP) {
			edge = NO_TUNNEL;
			goto next;
		}
		if (gr_mbuf_is_traced(mbuf)) {
			struct trace_ipip_data *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->iface_id = iface->id;
		}
		ip_data->input_iface = iface;
		ipip = (const struct iface_info_ipip *)iface->info;

		// Encapsulate with another IPv4 header.
		inner = rte_pktmbuf_mtod(mbuf, const struct rte_ipv4_hdr *);
		tunnel.src = ipip->local;
		tunnel.dst = ipip->remote;
		tunnel.len = rte_be_to_cpu_16(inner->total_length);
		tunnel.vrf_id = iface->vrf_id;
		tunnel.proto = IPPROTO_IPIP;
		tunnel.ttl = IPV4_DEFAULT_TTL;
		outer = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*outer));
		if (unlikely(outer == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		ip_set_fields(outer, &tunnel);

		// Resolve nexthop for the encapsulated packet.
		ip_data->nh = ip4_route_lookup(iface->vrf_id, ipip->remote);
		edge = IP_OUTPUT;

next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void ipip_output_register(void) {
	ip_output_add_tunnel(GR_IFACE_TYPE_IPIP, "ipip_output");
}

static struct rte_node_register ipip_output_node = {
	.name = "ipip_output",

	.process = ipip_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_OUTPUT] = "ip_output",
		[NO_TUNNEL] = "ipip_output_no_tunnel",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info ipip_output_info = {
	.node = &ipip_output_node,
	.register_callback = ipip_output_register,
	.trace_format = trace_ipip_format,
};

GR_NODE_REGISTER(ipip_output_info);

GR_DROP_REGISTER(ipip_output_no_tunnel);
