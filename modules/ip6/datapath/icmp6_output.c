// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_graph_worker.h>
#include <rte_ip.h>

#include <netinet/in.h>

enum {
	OUTPUT = 0,
	NO_HEADROOM,
	NO_ROUTE,
	EDGE_COUNT,
};

static uint16_t icmp6_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct ip6_output_mbuf_data *o;
	struct ip6_local_mbuf_data *d;
	const struct iface *iface;
	struct rte_ipv6_hdr *ip;
	struct rte_mbuf *mbuf;
	struct nexthop *nh;
	struct icmp6 *icmp6;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		d = ip6_local_mbuf_data(mbuf);

		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		ip = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));
		if (unlikely(ip == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}
		ip6_set_fields(ip, d->len, IPPROTO_ICMPV6, &d->src, &d->dst);
		// Compute ICMP6 checksum with pseudo header
		icmp6->cksum = 0;
		icmp6->cksum = rte_ipv6_udptcp_cksum(ip, icmp6);

		if (gr_mbuf_is_traced(mbuf)) {
			uint8_t trace_len = RTE_MIN(d->len, GR_TRACE_ITEM_MAX_LEN);
			struct icmp6 *t = gr_mbuf_trace_add(mbuf, node, trace_len);
			memcpy(t, icmp6, trace_len);
		}
		if ((nh = ip6_route_lookup(d->iface->vrf_id, d->iface->id, &d->dst)) == NULL) {
			edge = NO_ROUTE;
			goto next;
		}
		o = ip6_output_mbuf_data(mbuf);
		iface = d->iface;
		o->nh = nh;
		o->iface = iface;
		edge = OUTPUT;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register icmp6_output_node = {
	.name = "icmp6_output",

	.process = icmp6_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "ip6_output",
		[NO_HEADROOM] = "error_no_headroom",
		[NO_ROUTE] = "icmp6_output_no_route",
	},
};

static struct gr_node_info icmp6_output_info = {
	.node = &icmp6_output_node,
	.trace_format = (gr_trace_format_cb_t)trace_icmp6_format,
};

GR_NODE_REGISTER(icmp6_output_info);

GR_DROP_REGISTER(icmp6_output_no_route)
