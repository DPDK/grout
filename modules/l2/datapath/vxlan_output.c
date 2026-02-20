// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "l2_datapath.h"

#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_rxtx.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

enum {
	IP_OUTPUT = 0,
	NO_ROUTE,
	NO_HEADROOM,
	EDGE_COUNT,
};

#define EPHEMERAL_PORT_START 49152
#define EPHEMERAL_PORT_MASK (UINT16_MAX - EPHEMERAL_PORT_START)

static inline rte_be16_t vxlan_src_port(uint32_t hash) {
	// RFC 7348 Section 5, recommends using source port hashing to enable
	// ECMP load balancing in the underlay network.
	return rte_cpu_to_be_16(EPHEMERAL_PORT_START + (hash & EPHEMERAL_PORT_MASK));
}

static uint16_t vxlan_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface_info_vxlan *vxlan;
	struct iface_mbuf_data *d;
	struct vxlan_template *vh;
	const struct nexthop *nh;
	struct rte_mbuf *m;
	rte_edge_t edge;
	uint16_t len;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = iface_mbuf_data(m);
		vxlan = iface_info_vxlan(d->iface);

		if (gr_mbuf_is_traced(m)) {
			struct trace_vxlan_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->vni = rte_cpu_to_be_32(vxlan->vni);
			t->vtep = d->vtep;
		}

		nh = fib4_lookup(vxlan->encap_vrf_id, d->vtep);
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}

		len = rte_pktmbuf_pkt_len(m);

		vh = gr_mbuf_prepend(m, vh);
		if (unlikely(vh == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}

		*vh = vxlan->template;
		vh->udp.src_port = vxlan_src_port(m->hash.rss);
		vh->udp.dgram_len = rte_cpu_to_be_16(len + sizeof(vh->udp) + sizeof(vh->vxlan));
		vh->ip.dst_addr = d->vtep;
		vh->ip.total_length = rte_cpu_to_be_16(len + sizeof(*vh));
		vh->ip.hdr_checksum = rte_ipv4_cksum(&vh->ip);

		ip_output_mbuf_data(m)->nh = nh;

		edge = IP_OUTPUT;
next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void vxlan_output_register(void) {
	iface_output_type_register(GR_IFACE_TYPE_VXLAN, "vxlan_output");
}

static struct rte_node_register vxlan_output_node = {
	.name = "vxlan_output",

	.process = vxlan_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_OUTPUT] = "ip_output",
		[NO_ROUTE] = "vxlan_output_no_route",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info vxlan_output_info = {
	.node = &vxlan_output_node,
	.type = GR_NODE_T_L3,
	.register_callback = vxlan_output_register,
	.trace_format = trace_vxlan_format,
};

GR_NODE_REGISTER(vxlan_output_info);

GR_DROP_REGISTER(vxlan_output_no_route);
