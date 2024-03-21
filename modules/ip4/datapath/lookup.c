// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "mbuf_priv.h"

#include <br_datapath.h>
#include <br_graph.h>
#include <br_log.h>
#include <br_route4.h>

#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_rcu_qsbr.h>

enum edges {
	IP4_REWRITE = 0,
	BAD_CHECKSUM,
	BAD_LENGTH,
	NO_ROUTE,
	EDGE_COUNT,
};

static uint16_t
lookup_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_rcu_qsbr *rcu = node->ctx_ptr2;
	struct rte_fib *fib = node->ctx_ptr;
	struct rte_ipv4_hdr *hdr;
	struct rte_mbuf *mbuf;
	ip4_addr_t dst_addr;
	uint64_t next_hop;
	rte_edge_t next;
	uint16_t i;

	rte_rcu_qsbr_thread_online(rcu, rte_lcore_id());

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		next = IP4_REWRITE;

		trace_packet(node->name, mbuf);

		hdr = rte_pktmbuf_mtod_offset(
			mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr)
		);
		dst_addr = ntohl(hdr->dst_addr);

		// RFC 1812 section 5.2.2 IP Header Validation
		//
		// (1) The packet length reported by the Link Layer must be large
		//     enough to hold the minimum length legal IP datagram (20 bytes).
		// XXX: already checked by hardware

		// (2) The IP checksum must be correct.
		if ((mbuf->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_NONE) {
			// if this is not checked in H/W, check it.
			uint16_t actual_cksum, expected_cksum;
			actual_cksum = hdr->hdr_checksum;
			hdr->hdr_checksum = 0;
			expected_cksum = rte_ipv4_cksum(hdr);
			if (actual_cksum != expected_cksum) {
				next = BAD_CHECKSUM;
				goto next_packet;
			}
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
		if (rte_cpu_to_be_16(hdr->total_length) < sizeof(struct rte_ipv4_hdr)) {
			next = BAD_LENGTH;
			goto next_packet;
		}

		// TODO: optimize with lookup of multiple packets
		if (rte_fib_lookup_bulk(fib, &dst_addr, &next_hop, 1) < 0
		    || next_hop == BR_NO_ROUTE) {
			next = NO_ROUTE;
			goto next_packet;
		}

		ip4_fwd_mbuf_priv(mbuf)->next_hop = (ip4_addr_t)next_hop;
next_packet:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	rte_rcu_qsbr_thread_offline(rcu, rte_lcore_id());

	return nb_objs;
}

static const struct rte_mbuf_dynfield ip4_fwd_mbuf_priv_desc = {
	.name = "ip4_fwd",
	.size = sizeof(struct ip4_fwd_mbuf_priv),
	.align = __alignof__(struct ip4_fwd_mbuf_priv),
};

int ip4_fwd_mbuf_priv_offset = -1;

static int lookup_init(const struct rte_graph *graph, struct rte_node *node) {
	static bool once;

	(void)graph;

	if (!once) {
		once = true;
		ip4_fwd_mbuf_priv_offset = rte_mbuf_dynfield_register(&ip4_fwd_mbuf_priv_desc);
	}
	if (ip4_fwd_mbuf_priv_offset < 0) {
		LOG(ERR, "rte_mbuf_dynfield_register(): %s", rte_strerror(rte_errno));
		return -rte_errno;
	}
	node->ctx_ptr = rte_fib_find_existing(BR_IP4_FIB_NAME);
	if (node->ctx_ptr == NULL) {
		LOG(ERR, "rte_fib_find_existing(%s): %s", BR_IP4_FIB_NAME, rte_strerror(rte_errno));
		return -rte_errno;
	}
	node->ctx_ptr2 = br_route4_rcu();
	if (node->ctx_ptr2 == NULL) {
		LOG(ERR, "br_route4_rcu() == NULL");
		return -ENOENT;
	}

	return 0;
}

static void lookup_register(void) {
	rte_edge_t edge = br_node_attach_parent("eth_classify", "ipv4_lookup");
	if (edge == RTE_EDGE_ID_INVALID)
		ABORT("br_node_attach_parent(classify, ipv4_lookup) failed");
	br_classify_add_proto(RTE_PTYPE_L3_IPV4, edge);
	br_classify_add_proto(RTE_PTYPE_L3_IPV4_EXT, edge);
	br_classify_add_proto(RTE_PTYPE_L3_IPV4_EXT_UNKNOWN, edge);
	br_classify_add_proto(RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L2_ETHER, edge);
	br_classify_add_proto(RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L2_ETHER, edge);
	br_classify_add_proto(RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L2_ETHER, edge);
}

static struct rte_node_register lookup_node = {
	.name = "ipv4_lookup",

	.init = lookup_init,
	.process = lookup_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP4_REWRITE] = "ipv4_rewrite",
		[BAD_CHECKSUM] = "ipv4_lookup_bad_checksum",
		[BAD_LENGTH] = "ipv4_lookup_no_route",
		[NO_ROUTE] = "ipv4_lookup_bad_length",
	},
};

static struct br_node_info info = {
	.node = &lookup_node,
	.register_callback = lookup_register,
};

BR_NODE_REGISTER(info);

BR_DROP_REGISTER(ipv4_lookup_bad_checksum);
BR_DROP_REGISTER(ipv4_lookup_no_route);
BR_DROP_REGISTER(ipv4_lookup_bad_length);
