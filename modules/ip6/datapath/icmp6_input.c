// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>

enum {
	ICMP6_OUTPUT = 0,
	NEIGH_SOLICIT,
	NEIGH_ADVERT,
	BAD_CHECKSUM,
	INVALID,
	UNSUPPORTED,
	EDGE_COUNT,
};

static uint16_t
icmp6_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip6_local_mbuf_data *d;
	struct icmp6 *icmp6;
	struct rte_ipv6_addr tmp_ip;
	struct rte_mbuf *mbuf;
	rte_edge_t next;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		d = ip6_local_mbuf_data(mbuf);

		switch (icmp6->type) {
		case ICMP6_TYPE_ECHO_REQUEST:
			if (icmp6->code != 0) {
				next = INVALID;
				goto next;
			}
			icmp6->type = ICMP6_TYPE_ECHO_REPLY;
			// swap source/destination addresses
			rte_ipv6_addr_cpy(&tmp_ip, &d->dst);
			rte_ipv6_addr_cpy(&d->dst, &d->src);
			rte_ipv6_addr_cpy(&d->src, &tmp_ip);
			next = ICMP6_OUTPUT;
			break;
		case ICMP6_TYPE_NEIGH_SOLICIT:
			next = NEIGH_SOLICIT;
			break;
		case ICMP6_TYPE_NEIGH_ADVERT:
			next = NEIGH_ADVERT;
			break;
		case ICMP6_TYPE_ROUTER_SOLICIT:
		case ICMP6_TYPE_ROUTER_ADVERT:
		default:
			next = UNSUPPORTED;
		}
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static void icmp6_input_register(void) {
	ip6_input_local_add_proto(IPPROTO_ICMPV6, "icmp6_input");
}

static struct rte_node_register icmp6_input_node = {
	.name = "icmp6_input",

	.process = icmp6_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP6_OUTPUT] = "icmp6_output",
		[NEIGH_SOLICIT] = "ndp_ns_input",
		[NEIGH_ADVERT] = "ndp_na_input",
		[BAD_CHECKSUM] = "icmp6_input_bad_checksum",
		[INVALID] = "icmp6_input_invalid",
		[UNSUPPORTED] = "icmp6_input_unsupported",
	},
};

static struct gr_node_info icmp6_input_info = {
	.node = &icmp6_input_node,
	.register_callback = icmp6_input_register,
};

GR_NODE_REGISTER(icmp6_input_info);

GR_DROP_REGISTER(icmp6_input_bad_checksum);
GR_DROP_REGISTER(icmp6_input_invalid);
GR_DROP_REGISTER(icmp6_input_unsupported);
