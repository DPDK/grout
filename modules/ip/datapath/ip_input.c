// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

enum edges {
	FORWARD = 0,
	OUTPUT,
	LOCAL,
	NO_ROUTE,
	BAD_CHECKSUM,
	BAD_LENGTH,
	OTHER_HOST,
	EDGE_COUNT,
};

static uint16_t
ip_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct eth_input_mbuf_data *e;
	struct ip_output_mbuf_data *d;
	const struct iface *iface;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	struct nexthop *nh;
	rte_edge_t edge;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		iface = NULL;
		nh = NULL;
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		e = eth_input_mbuf_data(mbuf);
		d = ip_output_mbuf_data(mbuf);
		iface = e->iface;

		// RFC 1812 section 5.2.2 IP Header Validation
		//
		// (1) The packet length reported by the Link Layer must be large
		//     enough to hold the minimum length legal IP datagram (20 bytes).
		// XXX: already checked by hardware

		// (2) The IP checksum must be correct.
		switch (mbuf->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) {
		case RTE_MBUF_F_RX_IP_CKSUM_NONE:
		case RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN:
			// if this is not checked in H/W, check it.
			if (rte_ipv4_cksum(ip)) {
				edge = BAD_CHECKSUM;
				goto next;
			}
			break;
		case RTE_MBUF_F_RX_IP_CKSUM_BAD:
			edge = BAD_CHECKSUM;
			goto next;
		}

		// (3) The IP version number must be 4.  If the version number is not 4
		//     then the packet may be another version of IP, such as IPng or
		//     ST-II.
		// (4) The IP header length field must be large enough to hold the
		//     minimum length legal IP datagram (20 bytes = 5 words).
		// XXX: already checked by hardware

		// (5) The IP total length field must be large enough to hold the IP
		//     datagram header, whose length is specified in the IP header
		//     length field.
		if (rte_cpu_to_be_16(ip->total_length) < sizeof(struct rte_ipv4_hdr)) {
			edge = BAD_LENGTH;
			goto next;
		}

		switch (e->domain) {
		case ETH_DOMAIN_LOOPBACK:
		case ETH_DOMAIN_LOCAL:
			// Packet sent to our ethernet address.
			break;
		case ETH_DOMAIN_BROADCAST:
		case ETH_DOMAIN_MULTICAST:
			// Non unicast ethernet destination. No need for a route lookup.
			edge = LOCAL;
			goto next;
		case ETH_DOMAIN_OTHER:
		case ETH_DOMAIN_UNKNOWN:
			// Drop all packets not sent to our ethernet address
			edge = OTHER_HOST;
			goto next;
		}

		nh = fib4_lookup(iface->vrf_id, ip->dst_addr);
		if (nh == NULL) {
			edge = NO_ROUTE;
			goto next;
		}

		// If the resolved next hop is local and the destination IP is ourselves,
		// send to ip_local.
		if (nh->flags & GR_NH_F_LOCAL && ip->dst_addr == nh->ipv4)
			edge = LOCAL;
		else if (e->domain == ETH_DOMAIN_LOOPBACK)
			edge = OUTPUT;
		else
			edge = FORWARD;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_ipv4_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *ip;
		}
		// Store the resolved next hop for ip_output to avoid a second route lookup.
		d->nh = nh;
		d->iface = iface;
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void ip_input_register(void) {
	gr_eth_input_add_type(RTE_BE16(RTE_ETHER_TYPE_IPV4), "ip_input");
	loopback_input_add_type(RTE_BE16(RTE_ETHER_TYPE_IPV4), "ip_input");
}

static struct rte_node_register input_node = {
	.name = "ip_input",

	.process = ip_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[FORWARD] = "ip_forward",
		[OUTPUT] = "ip_output",
		[LOCAL] = "ip_input_local",
		[NO_ROUTE] = "ip_error_dest_unreach",
		[BAD_CHECKSUM] = "ip_input_bad_checksum",
		[BAD_LENGTH] = "ip_input_bad_length",
		[OTHER_HOST] = "ip_input_other_host",
	},
};

static struct gr_node_info info = {
	.node = &input_node,
	.register_callback = ip_input_register,
	.trace_format = (gr_trace_format_cb_t)trace_ip_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip_input_bad_checksum);
GR_DROP_REGISTER(ip_input_bad_length);
GR_DROP_REGISTER(ip_input_other_host);
