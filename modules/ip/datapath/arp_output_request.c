// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip4.h"
#include "rte_mbuf.h"

#include <br_datapath.h>
#include <br_eth_output.h>
#include <br_graph.h>
#include <br_iface.h>
#include <br_ip4_control.h>
#include <br_log.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_spinlock.h>

enum {
	OUTPUT = 0,
	FULL,
	ERROR,
	EDGE_COUNT,
};

typedef enum {
	OK_TO_SEND,
	HELD,
	HOLD_QUEUE_FULL,
} hold_status_t;

static inline hold_status_t hold_packet(struct nexthop *nh, struct rte_mbuf *mbuf) {
	hold_status_t status;

	rte_spinlock_lock(&nh->lock);

	if (nh->flags & BR_IP4_NH_F_REACHABLE) {
		// The next hop somehow became reachable after it was moved here from ip_output.
		struct eth_output_mbuf_data *data = eth_output_mbuf_data(mbuf);
		rte_ether_addr_copy(&nh->lladdr, &data->dst);
		data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		data->iface = iface_from_id(nh->iface_id);
		status = OK_TO_SEND;
	} else if (nh->n_held_pkts < IP4_NH_MAX_HELD_PKTS) {
		// TODO: Implement this as a tail queue to preserve ordering.
		if (nh->held_pkts == NULL) {
			nh->held_pkts = mbuf;
		} else {
			br_mbuf_priv(mbuf)->next = nh->held_pkts;
			nh->held_pkts = mbuf;
		}
		nh->n_held_pkts++;
		status = HELD;
	} else {
		status = HOLD_QUEUE_FULL;
	}

	rte_spinlock_unlock(&nh->lock);

	return status;
}

static uint16_t arp_output_request_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct eth_output_mbuf_data *eth_data;
	struct nexthop *nh, *local;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *mbuf;
	uint16_t sent = 0;
	rte_edge_t next;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		nh = ip_output_mbuf_data(mbuf)->nh;
		if (nh == NULL) {
			// should never happen
			next = ERROR;
			goto next;
		}
		// Store packet in the next hop hold queue to be flushed upon reception
		// of an ARP request or reply from the destination IP.
		switch (hold_packet(nh, mbuf)) {
		case OK_TO_SEND:
			next = OUTPUT;
			goto next;
		case HOLD_QUEUE_FULL:
			next = FULL;
			goto next;
		case HELD:
			break;
		}

		// Create a brand new mbuf to hold the ARP request.
		mbuf = rte_pktmbuf_alloc(mbuf->pool);
		if (mbuf == NULL) {
			next = ERROR;
			goto next;
		}
		local = ip4_addr_get(nh->iface_id);
		if (local == NULL) {
			next = ERROR;
			goto next;
		}

		// Set all ARP request fields. TODO: upstream this in dpdk.
		arp = (struct rte_arp_hdr *)rte_pktmbuf_append(mbuf, sizeof(struct rte_arp_hdr));
		arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
		arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
		arp->arp_hlen = sizeof(struct eth_addr);
		arp->arp_plen = sizeof(ip4_addr_t);
		if (iface_get_eth_addr(local->iface_id, &arp->arp_data.arp_sha) < 0) {
			next = ERROR;
			goto next;
		}
		arp->arp_data.arp_sip = local->ip;
		memset(&arp->arp_data.arp_tha, 0xff, sizeof(arp->arp_data.arp_tha));
		arp->arp_data.arp_tip = nh->ip;

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(mbuf);
		rte_ether_addr_copy(&arp->arp_data.arp_tha, &eth_data->dst);
		eth_data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
		eth_data->iface = iface_from_id(nh->iface_id);

		next = OUTPUT;
		sent++;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return sent;
}

static struct rte_node_register arp_output_request_node = {
	.name = "arp_output_request",
	.process = arp_output_request_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "eth_output",
		[FULL] = "arp_queue_full",
		[ERROR] = "arp_output_error",
	},
};

static struct br_node_info arp_output_request_info = {
	.node = &arp_output_request_node,
};

BR_NODE_REGISTER(arp_output_request_info);

BR_DROP_REGISTER(arp_queue_full);
BR_DROP_REGISTER(arp_output_error);
