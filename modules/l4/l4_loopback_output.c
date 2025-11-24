// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

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
	REDIRECT = 0,
	NO_IFACE,
	BAD_PROTO,
	NO_HEADROOM,
	EDGE_COUNT,
};

static uint16_t l4_loopback_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *mbuf;
	struct mbuf_data *d;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		edge = REDIRECT;

		d = mbuf_data(mbuf);
		d->iface = get_vrf_iface(d->iface->vrf_id);
		if (!d->iface) {
			edge = NO_IFACE;
			goto next;
		}

		if (mbuf->packet_type & RTE_PTYPE_L3_IPV4) {
			struct ip_local_mbuf_data *d = ip_local_mbuf_data(mbuf);
			struct rte_ipv4_hdr *ip;
			ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));
			if (ip == NULL) {
				edge = NO_HEADROOM;
				goto next;
			}
			ip_set_fields(ip, d);
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
		} else {
			edge = BAD_PROTO;
		}

next:
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register l4_loopback_output_node = {
	.name = "l4_loopback_output",
	.process = l4_loopback_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[REDIRECT] = "loopback_output",
		[NO_IFACE] = "no_loop_iface",
		[BAD_PROTO] = "l4_bad_proto",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info info = {
	.node = &l4_loopback_output_node,
	.type = GR_NODE_T_L4,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(no_loop_iface);
GR_DROP_REGISTER(l4_bad_proto);
