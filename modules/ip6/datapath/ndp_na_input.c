// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip6.h>

enum {
	CONTROL = 0,
	INVAL,
	EDGE_COUNT,
};

static uint16_t ndp_na_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct control_output_mbuf_data *ctrl_data;
	struct icmp6_neigh_advert *na;
	struct ip6_local_mbuf_data *d;
	struct rte_ether_addr lladdr;
	const struct nexthop *remote;
	const struct iface *iface;
	struct rte_mbuf *mbuf;
	struct icmp6 *icmp6;
	bool lladdr_found;
	rte_edge_t edge;

#define ASSERT_NDP(condition)                                                                      \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			edge = INVAL;                                                              \
			goto next;                                                                 \
		}                                                                                  \
	} while (0)

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		d = ip6_local_mbuf_data(mbuf);
		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		iface = d->iface;
		na = PAYLOAD(icmp6);

		// Validation of Neighbor Advertisements
		// https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1.2
		//
		// - The IP Hop Limit field has a value of 255, i.e., the packet
		//   could not possibly have been forwarded by a router.
		ASSERT_NDP(d->hop_limit == 255);
		// - ICMP Checksum is valid. (already checked in icmp6_input)
		//
		// - ICMP Code is 0.
		ASSERT_NDP(icmp6->code == 0);
		// - ICMP length (derived from the IP length) is 24 or more octets.
		ASSERT_NDP(d->len >= 24);
		// - Target Address is not a multicast address.
		ASSERT_NDP(!rte_ipv6_addr_is_mcast(&na->target));
		// - If the IP Destination Address is a multicast address the
		//   Solicited flag is zero.
		ASSERT_NDP(!rte_ipv6_addr_is_mcast(&d->dst) || na->solicited == 0);

		// https://www.rfc-editor.org/rfc/rfc4861.html#section-7.2.5
		//
		// When a valid Neighbor Advertisement is received (either solicited or
		// unsolicited), the Neighbor Cache is searched for the target's entry.
		// If no entry exists, the advertisement SHOULD be silently discarded.
		// There is no need to create an entry if none exists, since the
		// recipient has apparently not initiated any communication with the
		// target.
		remote = ip6_nexthop_lookup(iface->vrf_id, iface->id, &na->target);
		ASSERT_NDP(remote != NULL);

		lladdr_found = icmp6_get_opt(
			mbuf, sizeof(*icmp6) + sizeof(*na), ICMP6_OPT_TARGET_LLADDR, &lladdr
		);
		// If the link layer has addresses and no Target Link-Layer Address
		// option is included, the receiving node SHOULD silently discard the
		// received advertisement.
		ASSERT_NDP(lladdr_found);

		ctrl_data = control_output_mbuf_data(mbuf);
		ctrl_data->iface = iface;
		ctrl_data->callback = ndp_probe_input_cb;
		edge = CONTROL;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ndp_na_input",

	.process = ndp_na_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL] = "control_output",
		[INVAL] = "ndp_na_input_inval",
	},
};

static struct gr_node_info info = {
	.node = &node,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ndp_na_input_inval);
