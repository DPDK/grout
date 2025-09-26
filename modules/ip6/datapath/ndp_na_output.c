// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_control_input.h>
#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip6.h>

enum {
	OUTPUT = 0,
	EDGE_COUNT,
};

static uint16_t ndp_na_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct nexthop *local, *remote;
	struct ip6_local_mbuf_data *d;
	struct icmp6_neigh_advert *na;
	struct icmp6_opt_lladdr *ll;
	struct nexthop_info_l3 *l3;
	const struct iface *iface;
	struct icmp6_opt *opt;
	struct rte_mbuf *mbuf;
	uint16_t payload_len;
	struct icmp6 *icmp6;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		local = ndp_na_output_mbuf_data(mbuf)->local;
		remote = ndp_na_output_mbuf_data(mbuf)->remote;
		iface = ndp_na_output_mbuf_data(mbuf)->iface;
		l3 = nexthop_info_l3(local);

		rte_pktmbuf_trim(mbuf, rte_pktmbuf_pkt_len(mbuf));

		// Fill ICMP6 layer.
		payload_len = sizeof(*icmp6) + sizeof(*na) + sizeof(*opt) + sizeof(*ll);
		icmp6 = (struct icmp6 *)rte_pktmbuf_append(mbuf, payload_len);
		icmp6->type = ICMP6_TYPE_NEIGH_ADVERT;
		icmp6->code = 0;
		na = PAYLOAD(icmp6);
		na->override = 1;
		na->router = 1;
		na->solicited = remote != NULL;
		na->target = l3->ipv6;
		opt = PAYLOAD(na);
		opt->type = ICMP6_OPT_TARGET_LLADDR;
		opt->len = ICMP6_OPT_LEN(sizeof(*opt) + sizeof(*ll));
		ll = PAYLOAD(opt);
		ll->mac = l3->mac;

		// Fill in IP local data
		d = ip6_local_mbuf_data(mbuf);
		d->iface = iface;
		d->src = l3->ipv6;
		if (remote == NULL) {
			// If the source of the solicitation is the unspecified address, the
			// node MUST set the Solicited flag to zero and multicast the
			// advertisement to the all-nodes address.
			d->dst = (struct rte_ipv6_addr)RTE_IPV6_ADDR_ALLNODES_LINK_LOCAL;
		} else {
			d->dst = nexthop_info_l3(remote)->ipv6;
		}
		d->len = payload_len;
		d->hop_limit = IP6_DEFAULT_HOP_LIMIT;
		d->proto = IPPROTO_ICMPV6;

		if (gr_mbuf_is_traced(mbuf)) {
			uint8_t trace_len = RTE_MIN(payload_len, GR_TRACE_ITEM_MAX_LEN);
			struct icmp6 *t = gr_mbuf_trace_add(mbuf, node, trace_len);
			memcpy(t, icmp6, trace_len);
		}
		rte_node_enqueue_x1(graph, node, OUTPUT, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ndp_na_output",

	.process = ndp_na_output_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "icmp6_output",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.trace_format = (gr_trace_format_cb_t)trace_icmp6_format,
};

GR_NODE_REGISTER(info);
