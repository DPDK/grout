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
#include <rte_ip6.h>

enum {
	CONTROL = 0,
	INVAL,
	DROP,
	EDGE_COUNT,
};

static uint16_t ndp_ns_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct control_output_mbuf_data *c;
	struct icmp6_neigh_solicit *ns;
	struct ip6_local_mbuf_data d;
	struct rte_ether_addr lladdr;
	const struct nexthop *local;
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

		d = *ip6_local_mbuf_data(mbuf);
		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		ns = PAYLOAD(icmp6);

		// Validation of Neighbor Solicitations
		// https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1.1
		//
		// - The IP Hop Limit field has a value of 255, i.e., the packet
		//   could not possibly have been forwarded by a router.
		ASSERT_NDP(d.hop_limit == 255);
		// - ICMP Checksum is valid. (already checked in icmp6_input)
		//
		// - ICMP Code is 0.
		ASSERT_NDP(icmp6->code == 0);
		// - ICMP length (derived from the IP length) is 24 or more octets.
		ASSERT_NDP(d.len >= 0);
		// - Target Address is not a multicast address.
		ASSERT_NDP(!rte_ipv6_addr_is_mcast(&ns->target));

		local = nh6_lookup(d.iface->vrf_id, d.iface->id, &ns->target);
		if (local == NULL || !(local->flags & GR_NH_F_LOCAL)) {
			next = DROP;
			if (gr_mbuf_is_traced(mbuf))
				gr_mbuf_trace_add(mbuf, node, 0);
			goto next;
		}

		if (rte_ipv6_addr_is_unspec(&d.src)) {
			// - If the IP source address is the unspecified address, the IP
			//   destination address is a solicited-node multicast address.
			ASSERT_NDP(rte_ipv6_addr_is_mcast(&d.dst));
			// - If the IP source address is the unspecified address, there is
			//   no source link-layer address option in the message.
			lladdr_found = icmp6_get_opt(
				mbuf, sizeof(*icmp6) + sizeof(*ns), ICMP6_OPT_SRC_LLADDR, &lladdr
			);
			ASSERT_NDP(!lladdr_found);
		}

		c = control_output_mbuf_data(mbuf);
		c->iface = d.iface;
		c->callback = ndp_probe_input_cb;
		memcpy(c->cb_data, &d, sizeof(d));
		next = CONTROL;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			uint8_t trace_len = RTE_MIN(d.len, GR_TRACE_ITEM_MAX_LEN);
			struct icmp6 *t = gr_mbuf_trace_add(mbuf, node, trace_len);
			memcpy(t, icmp6, trace_len);
		}
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ndp_ns_input",

	.process = ndp_ns_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL] = "control_output",
		[INVAL] = "ndp_ns_input_inval",
		[DROP] = "ndp_ns_input_drop",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.trace_format = (gr_trace_format_cb_t)trace_icmp6_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ndp_ns_input_inval);
GR_DROP_REGISTER(ndp_ns_input_drop);
