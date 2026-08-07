// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "control_input.h"
#include "eth.h"
#include "graph.h"
#include "l3.h"
#include "log.h"
#include "mbuf.h"
#include "mpls.h"
#include "mpls_datapath.h"

#include <rte_ether.h>
#include <rte_mbuf_ptype.h>

LOG_TYPE("mpls");

static control_input_t mpls_output_ctrl;

int mpls_resubmit_cb(struct rte_mbuf *m, struct nexthop *) {
	l3_mbuf_data(m)->nh = mpls_hold_mbuf_data(m)->mpls_nh;
	mbuf_data(m)->iface = NULL;
	if (post_to_stack(mpls_output_ctrl, m) < 0) {
		LOG(ERR, "post_to_stack: %s", strerror(errno));
		return -errno;
	}
	return 0;
}

enum {
	ETH_OUTPUT = 0,
	HOLD,
	NO_ROUTE,
	MTU_EXCEEDED,
	EDGE_COUNT,
};

static uint16_t
mpls_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_output_mbuf_data *eth_data;
	const struct nexthop_info_l3 *l3;
	const struct nexthop *via_nh;
	const struct nexthop *nh;
	const struct iface *iface;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		nh = l3_mbuf_data(mbuf)->nh;
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}

		if (nh->type == GR_NH_T_MPLS) {
			via_nh = nexthop_info_mpls(nh)->via_nh;
		} else if (nh->type == GR_NH_T_L3) {
			via_nh = nh;
		} else {
			edge = NO_ROUTE;
			goto next;
		}

		if (via_nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}

		l3 = nexthop_info_l3(via_nh);
		iface = iface_from_id(via_nh->iface_id);
		if (iface == NULL) {
			edge = NO_ROUTE;
			goto next;
		}

		if (rte_pktmbuf_pkt_len(mbuf) > iface->mtu) {
			edge = MTU_EXCEEDED;
			goto next;
		}

		if (l3->state != GR_NH_S_REACHABLE) {
			mpls_hold_mbuf_data(mbuf)->mpls_nh = nh;
			l3_mbuf_data(mbuf)->nh = via_nh;
			mbuf->packet_type |= RTE_PTYPE_TUNNEL_MPLS_IN_GRE;
			edge = HOLD;
			goto next;
		}

		eth_data = eth_output_mbuf_data(mbuf);
		eth_data->dst = l3->mac;
		if (mbuf->packet_type & RTE_PTYPE_L3_IPV4)
			eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
		else if (mbuf->packet_type & RTE_PTYPE_L3_IPV6)
			eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);
		else
			eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_MPLS);
		mbuf_data(mbuf)->iface = iface;
		edge = ETH_OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register mpls_output_node_reg = {
	.name = "mpls_output",

	.process = mpls_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ETH_OUTPUT] = "eth_output",
		[HOLD] = "ip_hold",
		[NO_ROUTE] = "mpls_output_no_route",
		[MTU_EXCEEDED] = "mpls_output_mtu_exceeded",
	},
};

static void mpls_output_register(void) {
	mpls_output_ctrl = gr_control_input_register_handler("mpls_output", true);
}

static struct gr_node_info info = {
	.node = &mpls_output_node_reg,
	.type = GR_NODE_T_L3,
	.register_callback = mpls_output_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(mpls_output_no_route);
GR_DROP_REGISTER(mpls_output_mtu_exceeded);
