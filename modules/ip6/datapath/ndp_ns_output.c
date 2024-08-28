// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_control_input.h>
#include <gr_datapath.h>
#include <gr_eth_output.h>
#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_iface.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_macro.h>

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_spinlock.h>

enum {
	OUTPUT = 0,
	ERROR,
	EDGE_COUNT,
};

static control_input_t ndp_solicit;

int ip6_nexthop_solicit(struct nexthop6 *nh) {
	if (nh == NULL)
		return errno_set(EINVAL);
	return post_to_stack(ndp_solicit, nh);
}

static uint16_t ndp_ns_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct icmp6_opt_lladdr *lladdr;
	struct icmp6_neigh_solicit *ns;
	struct nexthop6 *local, *nh;
	struct rte_ipv6_addr dst;
	struct rte_ipv6_hdr *ip;
	struct rte_mbuf *mbuf;
	struct icmp6_opt *opt;
	uint16_t payload_len;
	struct icmp6 *icmp6;
	rte_edge_t next;

	for (unsigned i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		nh = control_input_mbuf_data(mbuf)->data;
		if (nh == NULL) {
			next = ERROR;
			goto next;
		}
		local = ip6_addr_get_preferred(nh->iface_id, &nh->ip);
		if (local == NULL) {
			next = ERROR;
			goto next;
		}

		// Fill ICMP6 layer.
		icmp6 = (struct icmp6 *)rte_pktmbuf_append(mbuf, sizeof(*icmp6));
		icmp6->type = ICMP6_TYPE_NEIGH_SOLICIT;
		icmp6->code = 0;
		ns = (struct icmp6_neigh_solicit *)rte_pktmbuf_append(mbuf, sizeof(*ns));
		ns->__reserved = 0;
		rte_ipv6_addr_cpy(&ns->target, &nh->ip);
		opt = (struct icmp6_opt *)rte_pktmbuf_append(mbuf, sizeof(*opt));
		opt->type = ICMP6_OPT_SRC_LLADDR;
		opt->len = ICMP6_OPT_LEN(sizeof(*opt) + sizeof(*lladdr));
		lladdr = (struct icmp6_opt_lladdr *)rte_pktmbuf_append(mbuf, sizeof(*lladdr));
		rte_ether_addr_copy(&local->lladdr, &lladdr->mac);
		if (nh->last_reply != 0 && nh->ucast_probes < IP6_NH_UCAST_PROBES) {
			rte_ipv6_addr_cpy(&dst, &nh->ip);
			nh->ucast_probes++;
		} else {
			rte_ipv6_solnode_from_addr(&dst, &nh->ip);
			nh->mcast_probes++;
		}
		// Fill IPv6 layer
		payload_len = rte_pktmbuf_pkt_len(mbuf);
		ip = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ip));
		ip6_set_fields(ip, payload_len, IPPROTO_ICMPV6, &local->ip, &dst);
		// Compute ICMP6 checksum with pseudo header
		icmp6->cksum = 0;
		icmp6->cksum = rte_ipv6_udptcp_cksum(ip, icmp6);

		nh->last_request = rte_get_tsc_cycles();
		ip6_output_mbuf_data(mbuf)->nh = nh;
		next = OUTPUT;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static void ndp_output_solicit_register(void) {
	ndp_solicit = gr_control_input_register_handler("ndp_ns_output");
}

static struct rte_node_register node = {
	.name = "ndp_ns_output",
	.process = ndp_ns_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "ip6_output",
		[ERROR] = "ndp_ns_output_error",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.register_callback = ndp_output_solicit_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ndp_ns_output_error);
