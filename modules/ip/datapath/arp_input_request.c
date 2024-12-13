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
	IP_OUTPUT = 0,
	REPLY,
	DROP,
	ERROR,
	EDGE_COUNT,
};

static uint16_t arp_input_request_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct nexthop *remote, *local;
	struct arp_reply_mbuf_data *d;
	const struct iface *iface;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	ip4_addr_t sip;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		arp = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
		iface = mbuf_data(mbuf)->iface;
		local = ip4_nexthop_lookup(iface->vrf_id, arp->arp_data.arp_tip);
		if (local == NULL || !(local->flags & GR_NH_F_LOCAL)) {
			// ARP request not for us
			edge = DROP;
			goto next;
		}

		sip = arp->arp_data.arp_sip;
		remote = ip4_nexthop_lookup(iface->vrf_id, sip);
		if (remote == NULL) {
			// We don't have an entry for the ARP request sender address yet.
			//
			// Create one now. If the sender has requested our mac address,
			// they will certainly contact us soon and it will save us an
			// ARP request.
			if ((remote = ip4_nexthop_new(iface->vrf_id, iface->id, sip)) == NULL) {
				edge = ERROR;
				goto next;
			}
			// Add an internal /32 route to reference the newly created nexthop.
			if (ip4_route_insert(iface->vrf_id, sip, 32, remote) < 0) {
				edge = ERROR;
				goto next;
			}
		}
		arp_update_nexthop(graph, node, remote, iface, &arp->arp_data.arp_sha);

		edge = REPLY;
		d = arp_reply_mbuf_data(mbuf);
		d->local = local;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "arp_input_request",

	.process = arp_input_request_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_OUTPUT] = "ip_output",
		[REPLY] = "arp_output_reply",
		[DROP] = "arp_input_request_drop",
		[ERROR] = "arp_input_request_error",
	},
};

static struct gr_node_info info = {
	.node = &node,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(arp_input_request_drop);
GR_DROP_REGISTER(arp_input_request_error);
