// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip4_mbuf.h"

#include <br_datapath.h>
#include <br_graph.h>
#include <br_ip4.h>
#include <br_ip4_control.h>
#include <br_mbuf.h>
#include <br_tx.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum {
	TX = 0,
	NO_ROUTE,
	ERROR,
	ARP_REQUEST,
	EDGE_COUNT,
};

static uint16_t
output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct tx_mbuf_data *tx_data;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	struct next_hop *nh;
	rte_edge_t next;
	uint32_t idx;

	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);

		nh = ip_output_mbuf_data(mbuf)->nh; // from ip_input
		if (nh == NULL)
			nh = ip4_route_lookup(ip->dst_addr); // from arp_input
		if (nh == NULL) {
			next = NO_ROUTE;
			goto next;
		}
		if (nh->flags & BR_IP4_NH_F_LINK && ip->dst_addr != nh->ip) {
			// The resolved next hop is associated with a "connected" route.
			// We currently do not have an explicit entry for this destination IP.
			// Create a new next hop and its associated /32 route so that next
			// packets take it in priority with a single route lookup.
			struct next_hop *remote;
			if (ip4_next_hop_lookup_add(ip->dst_addr, &idx, &remote) < 0) {
				next = ERROR;
				goto next;
			}
			ip4_route_insert(ip->dst_addr, 32, idx, remote);
			remote->port_id = nh->port_id;
			ip_output_mbuf_data(mbuf)->nh = nh;
		}
		if (!(nh->flags & BR_IP4_NH_F_REACHABLE)) {
			next = ARP_REQUEST;
			goto next;
		}
		// Prepare ethernet layer info.
		tx_data = tx_mbuf_data(mbuf);
		rte_ether_addr_copy(&nh->lladdr, &tx_data->dst);
		tx_data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		mbuf->port = nh->port_id;
		next = TX;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

struct rte_node_register output_node = {
	.name = "ipv4_output",
	.process = output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[TX] = "eth_tx",
		[ERROR] = "ipv4_output_error",
		[NO_ROUTE] = "ipv4_output_no_route",
		[ARP_REQUEST] = "arp_output_request",
	},
};

static struct br_node_info info = {
	.node = &output_node,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(ipv4_output_error);
BR_DROP_REGISTER(ipv4_output_no_route);
