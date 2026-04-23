// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "graph.h"
#include "ip4.h"
#include "ip6.h"
#include "l2.h"
#include "l2_datapath.h"
#include "l3.h"
#include "mbuf.h"
#include "rxtx.h"

#include <rte_byteorder.h>
#include <rte_ip6.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

enum {
	IP_OUTPUT = 0,
	IP6_OUTPUT,
	NO_ROUTE,
	NO_HEADROOM,
	NO_AF,
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
	struct vxlan_template_ipv4 *vh4;
	struct vxlan_template_ipv6 *vh6;
	struct iface_mbuf_data *d;
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

		len = rte_pktmbuf_pkt_len(m);

		switch (d->vtep.af) {
		case GR_AF_IP4:
			nh = fib4_lookup(vxlan->encap_vrf_id, d->vtep.ipv4);
			if (nh == NULL) {
				edge = NO_ROUTE;
				goto next;
			}

			vh4 = gr_mbuf_prepend(m, vh4);
			if (unlikely(vh4 == NULL)) {
				edge = NO_HEADROOM;
				goto next;
			}
			*vh4 = vxlan->template.ipv4;
			vh4->udp.src_port = vxlan_src_port(m->hash.rss);
			vh4->udp.dgram_len = rte_cpu_to_be_16(
				len + sizeof(vh4->udp) + sizeof(vh4->vxlan)
			);
			vh4->ip.dst_addr = d->vtep.ipv4;
			vh4->ip.total_length = rte_cpu_to_be_16(len + sizeof(*vh4));
			vh4->ip.hdr_checksum = rte_ipv4_cksum(&vh4->ip);

			edge = IP_OUTPUT;
			break;
		case GR_AF_IP6:
			nh = fib6_lookup(vxlan->encap_vrf_id, d->iface->id, &d->vtep.ipv6);
			if (nh == NULL) {
				edge = NO_ROUTE;
				goto next;
			}

			vh6 = gr_mbuf_prepend(m, vh6);
			if (unlikely(vh6 == NULL)) {
				edge = NO_HEADROOM;
				goto next;
			}
			*vh6 = vxlan->template.ipv6;
			vh6->udp.src_port = vxlan_src_port(m->hash.rss);
			vh6->udp.dgram_len = rte_cpu_to_be_16(
				len + sizeof(vh6->udp) + sizeof(vh6->vxlan)
			);
			vh6->ip.dst_addr = d->vtep.ipv6;
			vh6->ip.payload_len = vh6->udp.dgram_len;
			vh6->udp.dgram_cksum = rte_ipv6_udptcp_cksum(&vh6->ip, &vh6->udp);

			edge = IP6_OUTPUT;
			break;
		default:
			edge = NO_AF;
			goto next;
		}
		l3_mbuf_data(m)->nh = nh;
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
		[IP6_OUTPUT] = "ip6_output",
		[NO_ROUTE] = "vxlan_output_no_route",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_AF] = "vxlan_output_no_af",
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
GR_DROP_REGISTER(vxlan_output_no_af);
