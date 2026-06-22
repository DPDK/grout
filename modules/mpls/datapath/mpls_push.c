// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "graph.h"
#include "ip4_datapath.h"
#include "ip6_datapath.h"
#include "l3.h"
#include "mbuf.h"
#include "mpls.h"
#include "mpls_datapath.h"

#include <gr_mpls.h>

#include <rte_ip.h>
#include <rte_mpls.h>

enum {
	MPLS_OUTPUT = 0,
	NO_HEADROOM,
	FRAG_NEEDED,
	PKT_TOO_BIG,
	MTU_EXCEEDED,
	EDGE_COUNT,
};

static uint16_t
mpls_push_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct nexthop_info_mpls *info;
	struct rte_mpls_hdr *mpls;
	const struct iface *iface;
	struct rte_ipv6_hdr *ip6;
	struct rte_ipv4_hdr *ip4;
	const struct nexthop *nh;
	struct rte_mbuf *mbuf;
	uint16_t overhead;
	rte_edge_t edge;
	uint8_t ttl;
	uint8_t tc;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		nh = l3_mbuf_data(mbuf)->nh;
		info = nexthop_info_mpls(nh);

		if (info->n_labels == 0 || info->via_nh == NULL) {
			edge = NO_HEADROOM;
			goto next;
		}

		iface = iface_from_id(info->via_nh->iface_id);
		if (iface == NULL) {
			edge = NO_HEADROOM;
			goto next;
		}

		overhead = info->n_labels * sizeof(struct rte_mpls_hdr);
		if (rte_pktmbuf_pkt_len(mbuf) + overhead > iface->mtu) {
			if (mbuf->packet_type & RTE_PTYPE_L3_IPV6) {
				edge = PKT_TOO_BIG;
			} else {
				ip4 = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
				edge = (ip4->fragment_offset
					& rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG)) ?
					FRAG_NEEDED :
					MTU_EXCEEDED;
			}
			goto next;
		}

		if (mbuf->packet_type & RTE_PTYPE_L3_IPV4) {
			ip4 = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
			ttl = ip4->time_to_live;
			tc = ip4->type_of_service >> 5;
		} else {
			ip6 = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
			ttl = ip6->hop_limits;
			tc = (rte_be_to_cpu_32(ip6->vtc_flow) >> 25) & 0x7;
		}

		if (info->ttl)
			ttl = info->ttl;

		mpls = gr_mbuf_prepend(mbuf, mpls, (info->n_labels - 1) * sizeof(*mpls));
		if (unlikely(mpls == NULL)) {
			edge = NO_HEADROOM;
			goto next;
		}

		for (uint8_t j = 0; j < info->n_labels; j++) {
			mpls_hdr_set_label(&mpls[j], info->labels[j]);
			mpls[j].tc = tc;
			mpls[j].bs = (j == info->n_labels - 1) ? 1 : 0;
			mpls[j].ttl = ttl;
		}

		l3_mbuf_data(mbuf)->nh = nh;
		mbuf->packet_type = RTE_PTYPE_TUNNEL_MPLS_IN_GRE;
		edge = MPLS_OUTPUT;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void mpls_push_register(void) {
	ip_output_register_nexthop_type(GR_NH_T_MPLS, "mpls_push");
	ip6_output_register_nexthop_type(GR_NH_T_MPLS, "mpls_push");
}

static struct rte_node_register mpls_push_node = {
	.name = "mpls_push",

	.process = mpls_push_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[MPLS_OUTPUT] = "mpls_output",
		[NO_HEADROOM] = "error_no_headroom",
		[FRAG_NEEDED] = "mpls_push_frag_needed",
		[PKT_TOO_BIG] = "mpls_push_pkt_too_big",
		[MTU_EXCEEDED] = "mpls_push_mtu_exceeded",
	},
};

static struct gr_node_info info = {
	.node = &mpls_push_node,
	.type = GR_NODE_T_L3,
	.register_callback = mpls_push_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(mpls_push_mtu_exceeded);
