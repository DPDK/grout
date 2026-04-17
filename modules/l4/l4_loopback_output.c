// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "control_output.h"
#include "graph.h"
#include "ip4_datapath.h"
#include "ip6_datapath.h"
#include "rxtx.h"

enum edges {
	REDIRECT = 0,
	CP_OUTPUT,
	NO_IFACE,
	BAD_PROTO,
	NO_HEADROOM,
	EDGE_COUNT,
};

static uint16_t l4_loopback_output_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *mbuf;
	struct mbuf_data *d;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		edge = REDIRECT;

		d = mbuf_data(mbuf);

		// Prepend IP header
		if (mbuf->packet_type & RTE_PTYPE_L3_IPV4) {
			struct ip_local_mbuf_data *ld = ip_local_mbuf_data(mbuf);
			struct rte_ipv4_hdr *ip;
			ip = gr_mbuf_prepend(mbuf, ip);
			if (ip == NULL) {
				edge = NO_HEADROOM;
				goto next;
			}
			ip_set_fields(ip, ld);
		} else if (mbuf->packet_type & RTE_PTYPE_L3_IPV6) {
			struct ip6_local_mbuf_data *ld = ip6_local_mbuf_data(mbuf);
			struct rte_ipv6_hdr *ip;
			ip = gr_mbuf_prepend(mbuf, ip);
			if (ip == NULL) {
				edge = NO_HEADROOM;
				goto next;
			}
			ip6_set_fields(ip, ld->len, ld->proto, &ld->src, &ld->dst);
			ip->hop_limits = ld->hop_limit;
		} else {
			edge = BAD_PROTO;
			goto next;
		}

		// If the packet arrived on a port with a TAP control plane
		// interface, send it there instead of the TUN loopback.
		// This allows SO_BINDTODEVICE sockets to receive replies
		// on the same device they are bound to.
		if (d->iface->cp_fd != 0) {
			struct rte_ether_addr mac;
			struct rte_ether_hdr *eth;
			rte_be16_t ether_type;

			if (mbuf->packet_type & RTE_PTYPE_L3_IPV4)
				ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
			else
				ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);

			eth = gr_mbuf_prepend(mbuf, eth);
			if (eth == NULL) {
				edge = NO_HEADROOM;
				goto next;
			}

			iface_get_eth_addr(d->iface, &mac);
			eth->dst_addr = mac;
			eth->src_addr = mac;
			eth->ether_type = ether_type;

			// No VLAN header is written to the TAP. Clear the residual
			// mbuf metadata so traces reflect the actual frame bytes.
			iface_mbuf_data(mbuf)->vlan_id = 0;

			control_output_set_cb(mbuf, iface_cp_tx, 0);
			edge = CP_OUTPUT;
			goto next;
		}

		// No TAP: send through TUN loopback
		d->iface = get_vrf_iface(d->iface->vrf_id);
		if (!d->iface) {
			edge = NO_IFACE;
			goto next;
		}

next:
		if (gr_mbuf_is_traced(mbuf)) {
			gr_mbuf_trace_add(mbuf, node, 0);
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register l4_loopback_output_node = {
	.name = "l4_loopback_output",
	.process = l4_loopback_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[REDIRECT] = "loopback_output",
		[CP_OUTPUT] = "control_output",
		[NO_IFACE] = "no_loop_iface",
		[BAD_PROTO] = "l4_bad_proto",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info info = {
	.node = &l4_loopback_output_node,
	.type = GR_NODE_T_L4,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(no_loop_iface);
GR_DROP_REGISTER(l4_bad_proto);
