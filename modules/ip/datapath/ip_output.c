// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_ip4.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_nat_datapath.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum {
	ETH_OUTPUT = 0,
	HOLD,
	NO_ROUTE,
	ERROR,
	FRAGMENT,
	FRAG_NEEDED,
	DROP,
	EDGE_COUNT,
};

static rte_edge_t iface_type_edges[UINT_NUM_VALUES(gr_iface_type_t)] = {ETH_OUTPUT};

void ip_output_register_interface_type(gr_iface_type_t type, const char *next_node) {
	const char *type_name = gr_iface_type_name(type);
	if (strcmp(type_name, "?") == 0)
		ABORT("invalid iface type=%u", type);
	if (iface_type_edges[type] != ETH_OUTPUT)
		ABORT("next node already registered for iface type=%s", type_name);
	LOG(DEBUG, "ip_output: iface_type=%s -> %s", type_name, next_node);
	iface_type_edges[type] = gr_node_attach_parent("ip_output", next_node);
}

static rte_edge_t nh_type_edges[UINT_NUM_VALUES(gr_nh_type_t)] = {ETH_OUTPUT};

void ip_output_register_nexthop_type(gr_nh_type_t type, const char *next_node) {
	const char *type_name = gr_nh_type_name(type);
	if (strcmp(type_name, "?") == 0)
		ABORT("invalid nexthop type=%u", type);
	if (nh_type_edges[type] != ETH_OUTPUT)
		ABORT("next node already registered for nexthop type=%s", type_name);
	LOG(DEBUG, "ip_output: nh_type=%s -> %s", type_name, next_node);
	nh_type_edges[type] = gr_node_attach_parent("ip_output", next_node);
}

static uint16_t
ip_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_output_mbuf_data *eth_data;
	const struct nexthop_info_l3 *l3;
	const struct iface *iface;
	const struct nexthop *nh;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	uint16_t i, sent;
	rte_edge_t edge;

	sent = 0;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);

		nh = ip_output_mbuf_data(mbuf)->nh;
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}

		mbuf->packet_type |= RTE_PTYPE_L3_IPV4;

		edge = nh_type_edges[nh->type];
		if (edge != ETH_OUTPUT)
			goto next;

		iface = iface_from_id(nh->iface_id);
		if (iface == NULL) {
			edge = ERROR;
			goto next;
		}

		mbuf_data(mbuf)->iface = iface;

		if (rte_pktmbuf_pkt_len(mbuf) > iface->mtu) {
			if (ip->fragment_offset & rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG)) {
				edge = FRAG_NEEDED;
			} else {
				edge = FRAGMENT;
			}
			goto next;
		}

		// Determine what is the next node based on the output interface type
		// By default, it will be eth_output unless another output node was registered.
		edge = iface_type_edges[iface->type];

		switch (snat44_process(iface, mbuf)) {
		case NAT_VERDICT_CONTINUE:
		case NAT_VERDICT_FINAL:
			break;
		case NAT_VERDICT_DROP:
			edge = DROP;
			break;
		}

		if (edge != ETH_OUTPUT)
			goto next;

		l3 = nexthop_info_l3(nh);

		if (l3->state != GR_NH_S_REACHABLE
		    || (l3->flags & GR_NH_F_LINK && ip->dst_addr != l3->ipv4)) {
			// The nexthop needs ARP resolution or it is associated with
			// a "connected" route (i.e. matching an address/prefix on
			// a local interface).
			//
			// In the later case, a new nexthop must be created along with
			// its internal /32 route.
			//
			// In both case, the packet must be sent to control plane.
			edge = HOLD;
			goto next;
		}

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		eth_data->dst = l3->mac;
		eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
		sent++;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_ipv4_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *ip;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return sent;
}

static struct rte_node_register output_node = {
	.name = "ip_output",
	.process = ip_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ETH_OUTPUT] = "eth_output",
		[HOLD] = "ip_hold",
		[NO_ROUTE] = "ip_error_dest_unreach",
		[ERROR] = "ip_output_error",
		[FRAGMENT] = "ip_fragment",
		[FRAG_NEEDED] = "ip_error_frag_needed",
		[DROP] = "ip_output_drop",
	},
};

static struct gr_node_info info = {
	.node = &output_node,
	.type = GR_NODE_T_L3,
	.trace_format = (gr_trace_format_cb_t)trace_ip_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip_output_error);
GR_DROP_REGISTER(ip_output_drop);
