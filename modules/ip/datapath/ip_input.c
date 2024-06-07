// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_eth_input.h>
#include <br_graph.h>
#include <br_ip4_control.h>
#include <br_ip4_datapath.h>
#include <br_log.h>

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
	LOCAL,
	NO_ROUTE,
	BAD_CHECKSUM,
	BAD_LENGTH,
	EDGE_COUNT,
};

static uint16_t
ip_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct iface *iface;
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	struct nexthop *nh;
	rte_edge_t next;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);

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
				next = BAD_CHECKSUM;
				goto next_packet;
			}
			break;
		case RTE_MBUF_F_RX_IP_CKSUM_BAD:
			next = BAD_CHECKSUM;
			goto next_packet;
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
			next = BAD_LENGTH;
			goto next_packet;
		}

		iface = eth_input_mbuf_data(mbuf)->iface;
		nh = ip4_route_lookup(iface->vrf_id, ip->dst_addr);
		if (nh == NULL) {
			next = NO_ROUTE;
			goto next_packet;
		}
		// If the resolved next hop is local and the destination IP is ourselves,
		// send to ip_local.
		if (nh->flags & BR_IP4_NH_F_LOCAL && ip->dst_addr == nh->ip)
			next = LOCAL;
		else
			next = FORWARD;
		// Store the resolved next hop for ip_output to avoid a second route lookup.
		ip_output_mbuf_data(mbuf)->nh = nh;
next_packet:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static void ip_input_register(void) {
	rte_edge_t edge = br_node_attach_parent("eth_input", "ip_input");
	if (edge == RTE_EDGE_ID_INVALID)
		ABORT("br_node_attach_parent(eth_input, ip_input) failed");
	br_eth_input_add_type(rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4), edge);
}

static struct rte_node_register input_node = {
	.name = "ip_input",

	.process = ip_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[FORWARD] = "ip_forward",
		[LOCAL] = "ip_input_local",
		[NO_ROUTE] = "ip_input_no_route",
		[BAD_CHECKSUM] = "ip_input_bad_checksum",
		[BAD_LENGTH] = "ip_input_bad_length",
	},
};

static struct br_node_info info = {
	.node = &input_node,
	.register_callback = ip_input_register,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(ip_input_no_route);
BR_DROP_REGISTER(ip_input_bad_checksum);
BR_DROP_REGISTER(ip_input_bad_length);
