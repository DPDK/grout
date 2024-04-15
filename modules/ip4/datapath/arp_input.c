// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "ip4_mbuf.h"

#include <br_datapath.h>
#include <br_graph.h>
#include <br_ip4_control.h>
#include <br_log.h>
#include <br_mbuf.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>

enum {
	OP_REQUEST = 0,
	OP_REPLY,
	OP_UNSUPPORTED,
	PROTO_UNSUPPORTED,
	IP_OUTPUT,
	EDGE_COUNT,
};

static inline void update_nexthop(
	struct rte_graph *graph,
	struct rte_node *node,
	struct nexthop *nh,
	uint64_t now,
	const struct rte_mbuf *mbuf,
	const struct rte_arp_hdr *arp
) {
	struct br_mbuf_priv *priv;
	struct rte_mbuf *m;

	// Static next hops never need updating.
	if (nh->flags & BR_IP4_NH_F_STATIC)
		return;

	rte_spinlock_lock(&nh->lock);

	// Refresh all fields.
	nh->last_seen = now;
	nh->port_id = mbuf->port;
	nh->flags |= BR_IP4_NH_F_REACHABLE;
	nh->flags &= ~(BR_IP4_NH_F_STALE | BR_IP4_NH_F_PENDING);
	rte_ether_addr_copy(&arp->arp_data.arp_sha, &nh->lladdr);

	// Flush all held packets.
	m = nh->held_pkts;
	while (m != NULL) {
		rte_node_enqueue_x1(graph, node, IP_OUTPUT, m);
		// TODO: Implement this as a tail queue to preserve ordering.
		priv = br_mbuf_priv(m);
		m = priv->next;
		priv->next = NULL;
	}
	nh->held_pkts = NULL;
	nh->n_held_pkts = 0;

	rte_spinlock_unlock(&nh->lock);
}

static uint16_t
arp_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct nexthop *remote, *local;
	struct arp_mbuf_data *arp_data;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *mbuf;
	rte_edge_t next;
	uint32_t idx;
	uint64_t now;

	now = rte_get_tsc_cycles();

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		// ARP protocol sanity checks.
		arp = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
		if (rte_be_to_cpu_16(arp->arp_hardware) != RTE_ARP_HRD_ETHER) {
			next = PROTO_UNSUPPORTED;
			goto next;
		}
		if (rte_be_to_cpu_16(arp->arp_protocol) != RTE_ETHER_TYPE_IPV4) {
			next = PROTO_UNSUPPORTED;
			goto next;
		}
		switch (rte_be_to_cpu_16(arp->arp_opcode)) {
		case RTE_ARP_OP_REQUEST:
			next = OP_REQUEST;
			break;
		case RTE_ARP_OP_REPLY:
			next = OP_REPLY;
			break;
		default:
			next = OP_UNSUPPORTED;
			goto next;
		}

		local = ip4_addr_get(mbuf->port);

		if (ip4_nexthop_lookup(arp->arp_data.arp_sip, &idx, &remote) >= 0) {
			update_nexthop(graph, node, remote, now, mbuf, arp);
		} else if (local != NULL && local->ip == arp->arp_data.arp_tip) {
			// Request/reply to our address but no next hop entry exists.
			// Create a new next hop and its associated /32 route to allow
			// faster lookups for next packets.
			if (ip4_nexthop_lookup_add(arp->arp_data.arp_sip, &idx, &remote) < 0)
				goto next;
			ip4_route_insert(arp->arp_data.arp_sip, 32, idx, remote);
			update_nexthop(graph, node, remote, now, mbuf, arp);
		}
		arp_data = arp_mbuf_data(mbuf);
		arp_data->local = local;
		arp_data->remote = remote;
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static void arp_input_register(void) {
	rte_edge_t edge = br_node_attach_parent("eth_classify", "arp_input");
	if (edge == RTE_EDGE_ID_INVALID)
		ABORT("br_node_attach_parent(classify, arp_input) failed");
	br_classify_add_proto(rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP), edge);
}

static struct rte_node_register arp_input_node = {
	.name = "arp_input",

	.process = arp_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OP_REQUEST] = "arp_output_reply",
		[OP_REPLY] = "arp_input_reply",
		[OP_UNSUPPORTED] = "arp_input_op_unsupported",
		[PROTO_UNSUPPORTED] = "arp_input_proto_unsupported",
		[IP_OUTPUT] = "ipv4_output",
	},
};

static struct br_node_info arp_input_info = {
	.node = &arp_input_node,
	.register_callback = arp_input_register,
};

BR_NODE_REGISTER(arp_input_info);

BR_DROP_REGISTER(arp_input_reply);
BR_DROP_REGISTER(arp_input_op_unsupported);
BR_DROP_REGISTER(arp_input_proto_unsupported);
