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
	QUEUE_FULL,
	EDGE_COUNT,
};

static rte_edge_t edges[128] = {ETH_OUTPUT};

void ip_output_add_tunnel(uint16_t iface_type_id, rte_edge_t edge) {
	edges[iface_type_id] = edge;
	LOG(DEBUG, "ip_output: iface_type=%u -> edge %u", iface_type_id, edge);
}

typedef enum {
	OK_TO_SEND,
	HELD,
	HOLD_QUEUE_FULL,
} hold_status_t;

static inline hold_status_t maybe_hold_packet(struct nexthop *nh, struct rte_mbuf *mbuf) {
	hold_status_t status;

	if (nh->flags & BR_IP4_NH_F_REACHABLE) {
		status = OK_TO_SEND;
	} else if (nh->held_pkts_num < IP4_NH_MAX_HELD_PKTS) {
		queue_mbuf_data(mbuf)->next = NULL;
		rte_spinlock_lock(&nh->lock);
		if (nh->held_pkts_head == NULL)
			nh->held_pkts_head = mbuf;
		else
			queue_mbuf_data(nh->held_pkts_tail)->next = mbuf;
		nh->held_pkts_tail = mbuf;
		nh->held_pkts_num++;
		rte_spinlock_unlock(&nh->lock);
		if (!(nh->flags & BR_IP4_NH_F_PENDING)) {
			arp_output_request_solicit(nh);
			nh->flags |= BR_IP4_NH_F_PENDING;
		}
		status = HELD;
	} else {
		status = HOLD_QUEUE_FULL;
	}

	return status;
}

static uint16_t
ip_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_output_mbuf_data *eth_data;
	const struct iface *iface;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	struct nexthop *nh;
	uint16_t i, sent;
	rte_edge_t next;
	uint32_t idx;

	sent = 0;

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

		switch (maybe_hold_packet(nh, mbuf)) {
		case HELD:
			// The packet was stored in the next hop hold queue to be flushed upon
			// reception of an ARP request or reply from the destination IP.
			continue;
		case HOLD_QUEUE_FULL:
			//
			next = QUEUE_FULL;
			goto next;
		case OK_TO_SEND:
			// Next hop is reachable.
			break;
		}

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		rte_ether_addr_copy(&nh->lladdr, &eth_data->dst);
		eth_data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		eth_data->iface = iface;
		sent++;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return sent;
}

struct rte_node_register output_node = {
	.name = "ip_output",
	.process = ip_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ETH_OUTPUT] = "eth_output",
		[ERROR] = "ip_output_error",
		[NO_ROUTE] = "ip_output_no_route",
		[QUEUE_FULL] = "arp_queue_full",
	},
};

static struct br_node_info info = {
	.node = &output_node,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(ip_output_error);
BR_DROP_REGISTER(ip_output_no_route);
BR_DROP_REGISTER(arp_queue_full);
