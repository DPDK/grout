// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "gr_l4.h"

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_port.h>
#include <gr_trace.h>

#include <rte_ip.h>
#include <rte_mbuf.h>

enum edges {
	MANAGEMENT = 0,
	BAD_PROTO,
	EDGE_COUNT,
};

static rte_edge_t udp_edges[65536] = {MANAGEMENT};

void l4_input_register_port(uint8_t proto, rte_be16_t port, const char *next_node) {
	uint16_t p = rte_be_to_cpu_16(port);
	LOG(DEBUG, "l4_input_register_port: proto=%hhu port=%hu -> %s", proto, p, next_node);
	switch (proto) {
	case IPPROTO_UDP:
		if (udp_edges[port] != MANAGEMENT)
			ABORT("next node already registered for udp port=%hu", p);
		udp_edges[port] = gr_node_attach_parent("l4_input_local", next_node);
		break;
	default:
		ABORT("proto not supported %hhu", proto);
	}
}

static uint16_t l4_input_local_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_udp_hdr *hdr;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint8_t proto;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		edge = BAD_PROTO;

		if (mbuf->packet_type & RTE_PTYPE_L3_IPV4)
			proto = ip_local_mbuf_data(mbuf)->proto;
		else if (mbuf->packet_type & RTE_PTYPE_L3_IPV6)
			proto = ip6_local_mbuf_data(mbuf)->proto;
		else
			goto next;

		if (proto != IPPROTO_UDP) {
			edge = MANAGEMENT;
			goto next;
		}

		hdr = rte_pktmbuf_mtod(mbuf, struct rte_udp_hdr *);
		edge = udp_edges[hdr->dst_port];
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}
	return nb_objs;
}

static void l4_input_local_register(void) {
	ip_input_local_add_proto(IPPROTO_UDP, "l4_input_local");
	ip_input_local_add_proto(IPPROTO_TCP, "l4_input_local");
	ip6_input_local_add_proto(IPPROTO_UDP, "l4_input_local");
	ip6_input_local_add_proto(IPPROTO_TCP, "l4_input_local");
}
static struct rte_node_register input_node = {
	.name = "l4_input_local",
	.process = l4_input_local_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[MANAGEMENT] = "l4_loopback_output",
		[BAD_PROTO] = "l4_bad_proto",
	},
};

static struct gr_node_info info = {
	.node = &input_node,
	.register_callback = l4_input_local_register,
};

GR_NODE_REGISTER(info);
