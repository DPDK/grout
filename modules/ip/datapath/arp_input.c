// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>

enum {
	OP_REQUEST = 0,
	OP_REPLY,
	OP_UNSUPP,
	PROTO_UNSUPP,
	ERROR,
	DROP,
	IP_OUTPUT,
	EDGE_COUNT,
};

static inline void update_nexthop(
	struct rte_graph *graph,
	struct rte_node *node,
	struct nexthop *nh,
	uint64_t now,
	uint16_t iface_id,
	const struct rte_arp_hdr *arp
) {
	struct ip_output_mbuf_data *o;
	struct rte_mbuf *m, *next;

	// Static next hops never need updating.
	if (nh->flags & GR_NH_F_STATIC)
		return;

	rte_spinlock_lock(&nh->lock);

	// Refresh all fields.
	nh->last_reply = now;
	nh->iface_id = iface_id;
	nh->flags |= GR_NH_F_REACHABLE;
	nh->flags &= ~(GR_NH_F_STALE | GR_NH_F_PENDING | GR_NH_F_FAILED);
	nh->ucast_probes = 0;
	nh->bcast_probes = 0;
	nh->lladdr = arp->arp_data.arp_sha;

	// Flush all held packets.
	m = nh->held_pkts_head;
	while (m != NULL) {
		next = queue_mbuf_data(m)->next;
		o = ip_output_mbuf_data(m);
		o->nh = nh;
		o->iface = NULL;
		rte_node_enqueue_x1(graph, node, IP_OUTPUT, m);
		m = next;
	}
	nh->held_pkts_head = NULL;
	nh->held_pkts_tail = NULL;
	nh->held_pkts_num = 0;

	rte_spinlock_unlock(&nh->lock);
}

static uint16_t
arp_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct nexthop *remote, *local;
	struct arp_mbuf_data *arp_data;
	const struct iface *iface;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	ip4_addr_t sip;
	uint64_t now;

	now = rte_get_tsc_cycles();

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		// ARP protocol sanity checks.
		arp = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
		if (rte_be_to_cpu_16(arp->arp_hardware) != RTE_ARP_HRD_ETHER) {
			edge = PROTO_UNSUPP;
			goto next;
		}
		if (rte_be_to_cpu_16(arp->arp_protocol) != RTE_ETHER_TYPE_IPV4) {
			edge = PROTO_UNSUPP;
			goto next;
		}
		switch (rte_be_to_cpu_16(arp->arp_opcode)) {
		case RTE_ARP_OP_REQUEST:
			edge = OP_REQUEST;
			break;
		case RTE_ARP_OP_REPLY:
			edge = OP_REPLY;
			break;
		default:
			edge = OP_UNSUPP;
			goto next;
		}

		sip = arp->arp_data.arp_sip;
		iface = eth_input_mbuf_data(mbuf)->iface;
		local = ip4_addr_get_preferred(iface->id, sip);
		remote = ip4_nexthop_lookup(iface->vrf_id, sip);

		if (remote != NULL && remote->ipv4 == sip) {
			update_nexthop(graph, node, remote, now, iface->id, arp);
		} else if (local != NULL && local->ipv4 == arp->arp_data.arp_tip) {
			// Request/reply to our address but no next hop entry exists.
			// Create a new next hop and its associated /32 route to allow
			// faster lookups for next packets.
			if ((remote = ip4_nexthop_new(iface->vrf_id, iface->id, sip)) == NULL) {
				edge = ERROR;
				goto next;
			}
			if (ip4_route_insert(iface->vrf_id, sip, 32, remote) < 0) {
				edge = ERROR;
				goto next;
			}
			update_nexthop(graph, node, remote, now, iface->id, arp);
		} else {
			edge = DROP;
			goto next;
		}
		arp_data = arp_mbuf_data(mbuf);
		arp_data->local = local;
		arp_data->remote = remote;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_arp_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *arp;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void arp_input_register(void) {
	gr_eth_input_add_type(RTE_BE16(RTE_ETHER_TYPE_ARP), "arp_input");
}

static struct rte_node_register node = {
	.name = "arp_input",

	.process = arp_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OP_REQUEST] = "arp_output_reply",
		[OP_REPLY] = "arp_input_reply",
		[OP_UNSUPP] = "arp_input_op_unsupp",
		[PROTO_UNSUPP] = "arp_input_proto_unsupp",
		[ERROR] = "arp_input_error",
		[DROP] = "arp_input_drop",
		[IP_OUTPUT] = "ip_output",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.register_callback = arp_input_register,
	.trace_format = (gr_trace_format_cb_t)trace_arp_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(arp_input_reply);
GR_DROP_REGISTER(arp_input_op_unsupp);
GR_DROP_REGISTER(arp_input_proto_unsupp);
GR_DROP_REGISTER(arp_input_error);
GR_DROP_REGISTER(arp_input_drop);
