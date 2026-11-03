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
	NO_HEADROOM,
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
	const struct nexthop_info_mpls *info;
	struct nexthop_info_group *nhg;
	struct rte_mpls_hdr trace_hdr;
	const struct iface *iface;
	struct rte_mpls_hdr *mpls;
	const struct nexthop *nh;
	struct rte_ipv6_hdr *ip6;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	addr_family_t af;
	rte_edge_t edge;
	uint32_t label;
	uint8_t ver2;
	uint8_t bos;
	uint8_t ver;
	uint8_t ttl;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		edge = BAD_LABEL;

		trace_hdr = *rte_pktmbuf_mtod(mbuf, struct rte_mpls_hdr *);

		for (uint8_t depth = 0; depth < GR_MPLS_MAX_STACK_DEPTH; depth++) {
			mpls = rte_pktmbuf_mtod(mbuf, struct rte_mpls_hdr *);
			label = mpls_hdr_get_label(mpls);
			ttl = mpls->ttl;
			bos = mpls->bs;

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
					ver = *rte_pktmbuf_mtod(mbuf, uint8_t *) >> 4;
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
				case GR_MPLS_LABEL_ROUTER_ALERT:
					// RFC 2711: strip label and process payload if BOS,
					// otherwise continue to next label in stack.
					if (bos) {
						ver2 = *rte_pktmbuf_mtod(mbuf, uint8_t *) >> 4;
						if (ver2 == 4) {
							mbuf->packet_type = RTE_PTYPE_L3_IPV4;
							edge = IP_INPUT;
						} else if (ver2 == 6) {
							mbuf->packet_type = RTE_PTYPE_L3_IPV6;
							edge = IP6_INPUT;
						} else {
							edge = BAD_LABEL;
						}
						break;
					}
					continue;
				default:
					edge = BAD_LABEL;
					break;
				}
				break;
			}

			iface = mbuf_data(mbuf)->iface;
			nh = mpls_fib_lookup(iface->vrf_id, label);
			if (nh == NULL) {
				edge = NO_ROUTE;
				break;
			}

			if (nh->type == GR_NH_T_GROUP) {
				nhg = nexthop_info_group(nh);
				nh = nexthop_group_get_nh(nhg, mbuf->hash.rss);
				if (nh == NULL) {
					edge = NO_ROUTE;
					break;
				}
			}

			info = nexthop_info_mpls(nh);

			if (info->n_labels > 0) {
				if (info->n_labels > 1) {
					mpls = gr_mbuf_prepend(
						mbuf, mpls, (info->n_labels - 1) * sizeof(*mpls)
					);
					if (unlikely(mpls == NULL)) {
						edge = NO_HEADROOM;
						break;
					}
				}
				for (uint8_t k = 0; k < info->n_labels; k++) {
					mpls_hdr_set_label(&mpls[k], info->labels[k]);
					mpls[k].ttl = ttl;
					if (k < info->n_labels - 1) {
						mpls[k].bs = 0;
						mpls[k].tc = 0;
					}
				}
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
				af = info->payload_af;
				if (af == GR_AF_UNSPEC) {
					ver = *rte_pktmbuf_mtod(mbuf, uint8_t *) >> 4;
					if (ver == 4)
						af = GR_AF_IP4;
					else if (ver == 6)
						af = GR_AF_IP6;
				}
				if (af == GR_AF_IP4) {
					ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
					ip->hdr_checksum = fixup_checksum_16(
						ip->hdr_checksum,
						rte_cpu_to_be_16(ip->time_to_live << 8),
						rte_cpu_to_be_16(ttl << 8)
					);
					ip->time_to_live = ttl;
					mbuf->packet_type = RTE_PTYPE_L3_IPV4;
				} else if (af == GR_AF_IP6) {
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
		[NO_HEADROOM] = "error_no_headroom",
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
