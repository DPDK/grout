// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_datapath.h>
#include <gr_eth_input.h>
#include <gr_eth_output.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_ip4.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>

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

void ip_output_add_tunnel(uint16_t iface_type_id, const char *next_node) {
	LOG(DEBUG, "ip_output: iface_type=%u -> %s", iface_type_id, next_node);
	if (iface_type_id == GR_IFACE_TYPE_UNDEF || iface_type_id >= ARRAY_DIM(edges))
		ABORT("invalid iface type=%u", iface_type_id);
	if (edges[iface_type_id] != ETH_OUTPUT)
		ABORT("next node already registered for iface type=%u", iface_type_id);
	edges[iface_type_id] = gr_node_attach_parent("ip_output", next_node);
}

typedef enum {
	OK_TO_SEND,
	HELD,
	HOLD_QUEUE_FULL,
} hold_status_t;

static inline hold_status_t maybe_hold_packet(struct nexthop *nh, struct rte_mbuf *mbuf) {
	hold_status_t status;

	if (nh->flags & GR_IP4_NH_F_REACHABLE) {
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
		if (!(nh->flags & GR_IP4_NH_F_PENDING)) {
			arp_output_request_solicit(nh);
			nh->flags |= GR_IP4_NH_F_PENDING;
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
	rte_edge_t edge;

	sent = 0;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);

		nh = ip_output_mbuf_data(mbuf)->nh;
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}
		iface = iface_from_id(nh->iface_id);
		if (iface == NULL) {
			edge = ERROR;
			goto next;
		}
		// Determine what is the next node based on the output interface type
		// By default, it will be eth_output unless another output node was registered.
		edge = edges[iface->type_id];
		if (edge != ETH_OUTPUT)
			goto next;

		if (nh->flags & GR_IP4_NH_F_LINK && ip->dst_addr != nh->ip) {
			// The resolved next hop is associated with a "connected" route.
			// We currently do not have an explicit entry for this destination IP.
			// Create a new next hop and its associated /32 route so that next
			// packets take it in priority with a single route lookup.
			struct nexthop *remote = ip4_nexthop_new(
				nh->vrf_id, nh->iface_id, ip->dst_addr
			);
			if (remote == NULL) {
				edge = ERROR;
				goto next;
			}
			if (ip4_route_insert(nh->vrf_id, ip->dst_addr, 32, remote) < 0) {
				edge = ERROR;
				goto next;
			}

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
			edge = QUEUE_FULL;
			goto next;
		case OK_TO_SEND:
			// Next hop is reachable.
			break;
		}

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		rte_ether_addr_copy(&nh->lladdr, &eth_data->dst);
		eth_data->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
		eth_data->iface = iface;
		sent++;
next:
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return sent;
}

static struct rte_node_register output_node = {
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

static struct gr_node_info info = {
	.node = &output_node,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip_output_error);
GR_DROP_REGISTER(ip_output_no_route);
GR_DROP_REGISTER(arp_queue_full);
