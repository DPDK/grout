// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "checksum.h"
#include "eth.h"
#include "graph.h"
#include "l3.h"
#include "mbuf.h"
#include "mpls.h"
#include "mpls_datapath.h"

#include <gr_mpls.h>

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_mpls.h>

enum {
	MPLS_OUTPUT = 0,
	IP_INPUT,
	IP6_INPUT,
	TTL_EXCEEDED,
	NO_ROUTE,
	BAD_LABEL,
	EDGE_COUNT,
};

struct trace_mpls_data {
	uint32_t label;
	uint8_t tc;
	uint8_t bs;
	uint8_t ttl;
};

static int mpls_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_mpls_data *t = data;
	return snprintf(buf, len, "label=%u tc=%u bs=%u ttl=%u", t->label, t->tc, t->bs, t->ttl);
}

static uint16_t
mpls_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_mpls_hdr *mpls;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		edge = BAD_LABEL;

		struct rte_mpls_hdr trace_hdr = *rte_pktmbuf_mtod(mbuf, struct rte_mpls_hdr *);

		for (uint8_t depth = 0; depth < GR_MPLS_MAX_STACK_DEPTH; depth++) {
			mpls = rte_pktmbuf_mtod(mbuf, struct rte_mpls_hdr *);
			uint32_t label = mpls_hdr_get_label(mpls);
			uint8_t bos = mpls->bs;
			uint8_t ttl = mpls->ttl;

			if (ttl <= 1) {
				edge = TTL_EXCEEDED;
				break;
			}
			ttl -= 1;

			if (label < GR_MPLS_LABEL_FIRST_UNRESERVED) {
				rte_pktmbuf_adj(mbuf, sizeof(*mpls));
				switch (label) {
				case GR_MPLS_LABEL_IPV4_EXPLICIT_NULL:
					mbuf->packet_type = RTE_PTYPE_L3_IPV4;
					edge = IP_INPUT;
					break;
				case GR_MPLS_LABEL_IPV6_EXPLICIT_NULL:
					mbuf->packet_type = RTE_PTYPE_L3_IPV6;
					edge = IP6_INPUT;
					break;
				case GR_MPLS_LABEL_IMPLICIT_NULL:;
					uint8_t ver = *rte_pktmbuf_mtod(mbuf, uint8_t *) >> 4;
					if (ver == 4) {
						mbuf->packet_type = RTE_PTYPE_L3_IPV4;
						edge = IP_INPUT;
					} else if (ver == 6) {
						mbuf->packet_type = RTE_PTYPE_L3_IPV6;
						edge = IP6_INPUT;
					} else {
						edge = BAD_LABEL;
					}
					break;
				default:
					edge = BAD_LABEL;
					break;
				}
				break;
			}

			const struct iface *iface = mbuf_data(mbuf)->iface;
			const struct nexthop *nh = mpls_fib_lookup(iface->vrf_id, label);
			if (nh == NULL) {
				edge = NO_ROUTE;
				break;
			}

			const struct nexthop_info_mpls *info = nexthop_info_mpls(nh);

			if (info->n_labels > 0) {
				mpls_hdr_set_label(mpls, info->labels[0]);
				mpls->ttl = ttl;
				l3_mbuf_data(mbuf)->nh = nh;
				mbuf->packet_type = RTE_PTYPE_TUNNEL_MPLS_IN_GRE;
				edge = MPLS_OUTPUT;
				break;
			}

			if (bos) {
				if (info->via_nh == NULL) {
					edge = NO_ROUTE;
					break;
				}
				rte_pktmbuf_adj(mbuf, sizeof(*mpls));
				addr_family_t af = info->payload_af;
				if (af == GR_AF_UNSPEC) {
					uint8_t ver = *rte_pktmbuf_mtod(mbuf, uint8_t *) >> 4;
					if (ver == 4)
						af = GR_AF_IP4;
					else if (ver == 6)
						af = GR_AF_IP6;
				}
				if (af == GR_AF_IP4) {
					struct rte_ipv4_hdr *ip;
					ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
					ip->hdr_checksum = fixup_checksum_16(
						ip->hdr_checksum,
						rte_cpu_to_be_16(ip->time_to_live << 8),
						rte_cpu_to_be_16(ttl << 8)
					);
					ip->time_to_live = ttl;
					mbuf->packet_type = RTE_PTYPE_L3_IPV4;
				} else if (af == GR_AF_IP6) {
					struct rte_ipv6_hdr *ip6;
					ip6 = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
					ip6->hop_limits = ttl;
					mbuf->packet_type = RTE_PTYPE_L3_IPV6;
				} else {
					edge = BAD_LABEL;
					break;
				}
				l3_mbuf_data(mbuf)->nh = info->via_nh;
				edge = MPLS_OUTPUT;
				break;
			}

			rte_pktmbuf_adj(mbuf, sizeof(*mpls));
		}

		if (gr_mbuf_is_traced(mbuf)) {
			struct trace_mpls_data *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->label = mpls_hdr_get_label(&trace_hdr);
			t->tc = trace_hdr.tc;
			t->bs = trace_hdr.bs;
			t->ttl = trace_hdr.ttl;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void mpls_input_register(void) {
	gr_eth_input_add_type(RTE_BE16(RTE_ETHER_TYPE_MPLS), "mpls_input");
}

static struct rte_node_register mpls_input_node = {
	.name = "mpls_input",

	.process = mpls_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[MPLS_OUTPUT] = "mpls_output",
		[IP_INPUT] = "ip_input",
		[IP6_INPUT] = "ip6_input",
		[TTL_EXCEEDED] = "mpls_input_ttl_exceeded",
		[NO_ROUTE] = "mpls_input_no_route",
		[BAD_LABEL] = "mpls_input_bad_label",
	},
};

static struct gr_node_info info = {
	.node = &mpls_input_node,
	.type = GR_NODE_T_L3,
	.trace_format = mpls_trace_format,
	.register_callback = mpls_input_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(mpls_input_ttl_exceeded);
GR_DROP_REGISTER(mpls_input_no_route);
GR_DROP_REGISTER(mpls_input_bad_label);
