// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

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
	IP_OUTPUT = 0,
	INVAL,
	EDGE_COUNT,
};

// Declaration in gr_ip6_datapath.h. This function is shared with ndp_ns_input.
void ndp_update_nexthop(
	struct rte_graph *graph,
	struct rte_node *node,
	struct nexthop6 *nh,
	const struct iface *iface,
	const struct rte_ether_addr *mac
) {
	struct ip6_output_mbuf_data *d;
	struct rte_mbuf *m, *next;

	// Static next hops never need updating.
	if (nh->flags & GR_IP6_NH_F_STATIC)
		return;

	rte_spinlock_lock(&nh->lock);

	// Refresh all fields.
	nh->last_reply = rte_get_tsc_cycles();
	nh->iface_id = iface->id;
	nh->flags |= GR_IP6_NH_F_REACHABLE;
	nh->flags &= ~(GR_IP6_NH_F_STALE | GR_IP6_NH_F_PENDING | GR_IP6_NH_F_FAILED);
	nh->ucast_probes = 0;
	nh->mcast_probes = 0;
	nh->lladdr = *mac;

	// Flush all held packets.
	m = nh->held_pkts_head;
	while (m != NULL) {
		next = queue_mbuf_data(m)->next;
		d = ip6_output_mbuf_data(m);
		d->nh = nh;
		d->input_iface = NULL;
		rte_node_enqueue_x1(graph, node, IP_OUTPUT, m);
		m = next;
	}
	nh->held_pkts_head = NULL;
	nh->held_pkts_tail = NULL;
	nh->held_pkts_num = 0;

	rte_spinlock_unlock(&nh->lock);
}

static uint16_t ndp_na_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct icmp6_neigh_solicit *ns;
	struct icmp6_neigh_advert *na;
	struct ip6_local_mbuf_data *d;
	struct rte_ether_addr lladdr;
	const struct iface *iface;
	struct nexthop6 *remote;
	struct icmp6_opt *opt;
	struct rte_mbuf *mbuf;
	struct icmp6 *icmp6;
	bool lladdr_found;
	rte_edge_t next;

#define ASSERT_NDP(condition)                                                                      \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			next = INVAL;                                                              \
			goto next;                                                                 \
		}                                                                                  \
	} while (0)

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		d = ip6_local_mbuf_data(mbuf);
		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		iface = d->input_iface;
		na = (struct icmp6_neigh_advert *)rte_pktmbuf_adj(mbuf, sizeof(*icmp6));

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
		remote = ip6_nexthop_lookup(iface->vrf_id, &na->target);
		ASSERT_NDP(remote != NULL);

		opt = (struct icmp6_opt *)rte_pktmbuf_adj(mbuf, sizeof(*ns));
		lladdr_found = icmp6_get_opt(
			opt, rte_pktmbuf_pkt_len(mbuf), ICMP6_OPT_TARGET_LLADDR, &lladdr
		);
		// If the link layer has addresses and no Target Link-Layer Address
		// option is included, the receiving node SHOULD silently discard the
		// received advertisement.
		ASSERT_NDP(lladdr_found);

		ndp_update_nexthop(graph, node, remote, iface, &lladdr);

		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
			gr_mbuf_trace_finish(mbuf);
		}
		rte_pktmbuf_free(mbuf);
		continue;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ndp_na_input",

	.process = ndp_na_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_OUTPUT] = "ip6_output",
		[INVAL] = "ndp_na_input_inval",
	},
};

static struct gr_node_info info = {
	.node = &node,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ndp_na_input_inval);
