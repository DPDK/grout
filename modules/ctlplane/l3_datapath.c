// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_infra.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_port.h>
#include <gr_trace.h>

enum {
	L2_REDIRECT,
	NO_HEADROOM,
	BAD_PROTO,
	EDGE_COUNT,
};

static uint16_t
l3_redirect_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct iface_info_port *port;
	struct rte_ether_hdr *eth;
	uint16_t ether_type = 0;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		if (mbuf->packet_type & RTE_PTYPE_L3_IPV4) {
			struct ip_local_mbuf_data *d = ip_local_mbuf_data(mbuf);
			struct rte_ipv4_hdr *ip;
			ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));
			if (ip == NULL) {
				edge = NO_HEADROOM;
				goto next;
			}
			ip_set_fields(ip, d);
			ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
		} else if (mbuf->packet_type & RTE_PTYPE_L3_IPV6) {
			struct ip6_local_mbuf_data *d = ip6_local_mbuf_data(mbuf);
			struct rte_ipv6_hdr *ip;
			ip = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));
			if (ip == NULL) {
				edge = NO_HEADROOM;
				goto next;
			}
			ip6_set_fields(ip, d->len, d->proto, &d->src, &d->dst);
			ip->hop_limits = d->hop_limit;
			ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);
		} else {
			edge = BAD_PROTO;
		}
		edge = L2_REDIRECT;

		port = iface_info_port(mbuf_data(mbuf)->iface);

		eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*eth));
		if (unlikely(eth == NULL)) {
			edge = NO_HEADROOM;
		}
		eth->src_addr = port->mac;
		eth->dst_addr = port->mac;
		eth->ether_type = ether_type;

next:
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}
	return nb_objs;
}

static void l3_redirect_register(void) {
	ip_input_local_add_proto(GR_IPPROTO_OSPF, "l3_redirect");
	ip6_input_local_add_proto(GR_IPPROTO_OSPF, "l3_redirect");
}

static struct rte_node_register l3_redirect_node = {
	.name = "l3_redirect",
	.process = l3_redirect_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[L2_REDIRECT] = "l2_redirect",
		[NO_HEADROOM] = "error_no_headroom",
		[BAD_PROTO] = "l3_bad_proto",
	},
};

static struct gr_node_info l3_redirect_info = {
	.node = &l3_redirect_node,
	.register_callback = l3_redirect_register,
};

GR_NODE_REGISTER(l3_redirect_info);
GR_DROP_REGISTER(l3_bad_proto);
