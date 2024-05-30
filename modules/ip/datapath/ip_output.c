// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_datapath.h>
#include <br_eth_input.h>
#include <br_eth_output.h>
#include <br_graph.h>
#include <br_iface.h>
#include <br_ip4.h>
#include <br_ip4_control.h>
#include <br_ip4_datapath.h>
#include <br_mbuf.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

enum {
	ETH_OUTPUT = 0,
	NO_ROUTE,
	ERROR,
	ARP_REQUEST,
	EDGE_COUNT,
};

static rte_edge_t edges[128] = {ETH_OUTPUT};

void ip_output_add_tunnel(uint16_t iface_type_id, rte_edge_t edge) {
	edges[iface_type_id] = edge;
	LOG(DEBUG, "ip_output: iface_type=%u -> edge %u", iface_type_id, edge);
}

static uint16_t
output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_output_mbuf_data *eth_data;
	const struct iface *iface;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	struct nexthop *nh;
	rte_edge_t next;
	uint32_t idx;

	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);

		nh = ip_output_mbuf_data(mbuf)->nh;
		if (nh == NULL) {
			next = NO_ROUTE;
			goto next;
		}
		iface = iface_from_id(nh->iface_id);
		if (iface == NULL) {
			next = ERROR;
			goto next;
		}
		// Determine what is the next node based on the output interface type
		// By default, it will be eth_output unless another output node was registered.
		next = edges[iface->type_id];
		if (next != ETH_OUTPUT)
			goto next;

		if (nh->flags & BR_IP4_NH_F_LINK && ip->dst_addr != nh->ip) {
			// The resolved next hop is associated with a "connected" route.
			// We currently do not have an explicit entry for this destination IP.
			// Create a new next hop and its associated /32 route so that next
			// packets take it in priority with a single route lookup.
			struct nexthop *remote;
			if (ip4_nexthop_add(nh->vrf_id, ip->dst_addr, &idx, &remote) < 0) {
				next = ERROR;
				goto next;
			}
			ip4_route_insert(nh->vrf_id, ip->dst_addr, 32, idx, remote);
			remote->iface_id = nh->iface_id;
			ip_output_mbuf_data(mbuf)->nh = remote;
			nh = remote;
		}
		if (!(nh->flags & BR_IP4_NH_F_REACHABLE)) {
			next = ARP_REQUEST;
			goto next;
		}
		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		rte_ether_addr_copy(&nh->lladdr, &eth_data->dst);
		eth_data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		eth_data->iface = iface;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

struct rte_node_register output_node = {
	.name = "ip_output",
	.process = output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ETH_OUTPUT] = "eth_output",
		[ERROR] = "ip_output_error",
		[NO_ROUTE] = "ip_output_no_route",
		[ARP_REQUEST] = "arp_output_request",
	},
};

static struct br_node_info info = {
	.node = &output_node,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(ip_output_error);
BR_DROP_REGISTER(ip_output_no_route);
