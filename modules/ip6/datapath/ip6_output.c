// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_ip6.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_fib6.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum {
	ETH_OUTPUT = 0,
	HOLD,
	DEST_UNREACH,
	ERROR,
	TOO_BIG,
	EDGE_COUNT,
};

static rte_edge_t iface_type_edges[UINT_NUM_VALUES(gr_iface_type_t)] = {ETH_OUTPUT};

void ip6_output_register_interface_type(gr_iface_type_t type, const char *next_node) {
	const char *type_name = gr_iface_type_name(type);
	if (strcmp(type_name, "?") == 0)
		ABORT("invalid iface type=%u", type);
	if (iface_type_edges[type] != ETH_OUTPUT)
		ABORT("next node already registered for iface type=%s", type_name);
	LOG(DEBUG, "ip6_output: iface_type=%s -> %s", type_name, next_node);
	iface_type_edges[type] = gr_node_attach_parent("ip6_output", next_node);
}

static rte_edge_t nh_type_edges[UINT_NUM_VALUES(gr_nh_type_t)] = {ETH_OUTPUT};

void ip6_output_register_nexthop_type(gr_nh_type_t type, const char *next_node) {
	const char *type_name = gr_nh_type_name(type);
	if (strcmp(type_name, "?") == 0)
		ABORT("invalid nexthop type=%u", type);
	if (nh_type_edges[type] != ETH_OUTPUT)
		ABORT("next node already registered for nexthop type=%s", type_name);
	LOG(DEBUG, "ip6_output: nh_type=%s -> %s", type_name, next_node);
	nh_type_edges[type] = gr_node_attach_parent("ip6_output", next_node);
}

static uint16_t
ip6_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_output_mbuf_data *eth_data;
	const struct nexthop_info_l3 *l3;
	const struct iface *iface;
	const struct nexthop *nh;
	struct rte_ipv6_hdr *ip;
	struct rte_mbuf *mbuf;
	uint16_t i, sent;
	rte_edge_t edge;

	sent = 0;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);

		nh = ip6_output_mbuf_data(mbuf)->nh;
		if (nh == NULL) {
			edge = DEST_UNREACH;
			goto next;
		}

		mbuf->packet_type |= RTE_PTYPE_L3_IPV6;

		edge = nh_type_edges[nh->type];
		if (edge != ETH_OUTPUT)
			goto next;

		// For multicast destination, nh->iface will be NULL
		if (rte_ipv6_addr_is_mcast(&ip->dst_addr))
			iface = mbuf_data(mbuf)->iface;
		else
			iface = iface_from_id(nh->iface_id);
		if (iface == NULL) {
			edge = ERROR;
			goto next;
		}

		if (rte_pktmbuf_pkt_len(mbuf) > iface->mtu) {
			edge = TOO_BIG;
			goto next;
		}

		// Determine what is the next node based on the output interface type
		// By default, it will be eth_output unless another output node was registered.
		edge = iface_type_edges[iface->type];
		mbuf_data(mbuf)->iface = iface;
		if (edge != ETH_OUTPUT)
			goto next;

		l3 = nexthop_info_l3(nh);

		if (!rte_ipv6_addr_is_mcast(&ip->dst_addr)
		    && (l3->state != GR_NH_S_REACHABLE
			|| (l3->flags & GR_NH_F_LINK
			    && !rte_ipv6_addr_eq(&ip->dst_addr, &l3->ipv6)))) {
			edge = HOLD;
			goto next;
		}

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		if (rte_ipv6_addr_is_mcast(&ip->dst_addr))
			rte_ether_mcast_from_ipv6(&eth_data->dst, &ip->dst_addr);
		else
			eth_data->dst = l3->mac;
		eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);
		sent++;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_ipv6_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *ip;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return sent;
}

static struct rte_node_register output_node = {
	.name = "ip6_output",
	.process = ip6_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ETH_OUTPUT] = "eth_output",
		[HOLD] = "ip6_hold",
		[ERROR] = "ip6_output_error",
		[DEST_UNREACH] = "ip6_error_dest_unreach",
		[TOO_BIG] = "ip6_output_too_big",
	},
};

static struct gr_node_info info = {
	.node = &output_node,
	.type = GR_NODE_T_L3,
	.trace_format = (gr_trace_format_cb_t)trace_ip6_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip6_output_error);
GR_DROP_REGISTER(ip6_output_too_big);
