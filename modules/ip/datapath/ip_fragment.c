// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

// According to RFC 791:
// Every internet destination must be able to receive a datagram of 576 octets
// either in one piece or in fragments to be reassembled.
// With a jumbo frame (MTU set to 9000), we'd need 16 fragments.
#define MAX_FRAGMENTS 16

struct ip_fragment_trace_data {
	uint16_t packet_id;
	uint16_t frag_num;
	uint16_t offset;
	uint8_t more_frags;
};

enum {
	IP_OUTPUT = 0,
	NO_MBUF,
	ALREADY_FRAGMENTED,
	TOO_MANY_FRAGMENTS,
	ERROR,
	EDGE_COUNT,
};

static uint16_t
ip_fragment_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct rte_mbuf *mbuf, *frag_mbuf;
	struct rte_ipv4_hdr *ip, *frag_ip;
	uint16_t frag_size, frag_data_len;
	void *frags[MAX_FRAGMENTS];
	uint16_t data_len, offset;
	const struct iface *iface;
	uint16_t num_frags, i;
	uint16_t ip_hdr_len;
	uint16_t sent = 0;
	rte_edge_t edge;
	void *payload;

	for (uint16_t j = 0; j < nb_objs; j++) {
		mbuf = objs[j];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
		num_frags = 1;
		frags[0] = mbuf;

		// Check if packet is already a fragment - if so, just pass it through
		if (ip->fragment_offset
		    & RTE_BE16(RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK)) {
			// This is already a fragment, drop it
			edge = ALREADY_FRAGMENTED;
			goto next;
		}

		iface = mbuf_data(mbuf)->iface;
		assert(iface != NULL);

		ip_hdr_len = rte_ipv4_hdr_len(ip);
		data_len = rte_be_to_cpu_16(ip->total_length) - ip_hdr_len;

		// Calculate fragment payload size (multiple of 8, >= 8)
		uint16_t max_payload = (uint16_t)(iface->mtu - ip_hdr_len);
		frag_size = RTE_ALIGN_FLOOR(max_payload, 8);
		if (unlikely(frag_size < 8)) {
			edge = ERROR;
			goto next;
		}

		num_frags = (data_len + frag_size - 1) / frag_size;
		assert(num_frags > 1);
		if (num_frags > MAX_FRAGMENTS) {
			edge = TOO_MANY_FRAGMENTS;
			num_frags = 1;
			goto next;
		}

		// Prepare and enqueue first fragment (using original mbuf)
		ip->total_length = rte_cpu_to_be_16(ip_hdr_len + frag_size);
		ip->fragment_offset = RTE_BE16(RTE_IPV4_HDR_MF_FLAG);
		ip->hdr_checksum = 0;
		ip->hdr_checksum = rte_ipv4_cksum(ip);

		// First fragment trace will be handled last, and is already part
		// of the frags array at position 0.
		// Create remaining fragments
		for (i = 1; i < num_frags; i++) {
			// Create new fragment, copying the original IPv4 header.
			frag_mbuf = gr_mbuf_copy(
				mbuf, ip_hdr_len, sizeof(struct ip_output_mbuf_data)
			);
			if (unlikely(frag_mbuf == NULL)) {
				break;
			}

			frag_ip = rte_pktmbuf_mtod(frag_mbuf, struct rte_ipv4_hdr *);
			offset = i * frag_size;
			frag_data_len = RTE_MIN(frag_size, data_len - offset);

			payload = rte_pktmbuf_append(frag_mbuf, frag_data_len);
			if (unlikely(payload == NULL)) {
				rte_pktmbuf_free(frag_mbuf);
				break;
			}

			memcpy(payload,
			       rte_pktmbuf_mtod_offset(mbuf, const void *, ip_hdr_len + offset),
			       frag_data_len);

			frag_ip->total_length = rte_cpu_to_be_16(ip_hdr_len + frag_data_len);
			frag_ip->fragment_offset = rte_cpu_to_be_16(
				(offset / 8) | ((i < num_frags - 1) ? RTE_IPV4_HDR_MF_FLAG : 0)
			);
			frag_ip->hdr_checksum = 0;
			frag_ip->hdr_checksum = rte_ipv4_cksum(frag_ip);

			frag_mbuf->packet_type = mbuf->packet_type;
			if (gr_mbuf_is_traced(mbuf)) {
				struct ip_fragment_trace_data *t;
				t = gr_mbuf_trace_add(frag_mbuf, node, sizeof(*t));
				t->packet_id = rte_be_to_cpu_16(frag_ip->packet_id);
				t->frag_num = i;
				t->offset = offset;
				t->more_frags = (i < num_frags - 1) ? 1 : 0;
			}

			frags[i] = frag_mbuf;
		}
		// If we had an error, drop the whole mbuf.
		if (unlikely(i != num_frags)) {
			for (uint16_t j = 1; j < i; j++)
				rte_pktmbuf_free(frags[j]);
			edge = ERROR;
			num_frags = 1;
		} else {
			// Trim first fragment to the right size
			rte_pktmbuf_trim(mbuf, data_len - frag_size);
			edge = IP_OUTPUT;
		}

next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct ip_fragment_trace_data *t;
			t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			t->packet_id = rte_be_to_cpu_16(ip->packet_id);
			t->frag_num = 0;
			t->offset = 0;
			t->more_frags = (num_frags > 1) ? 1 : 0;
		}

		rte_node_enqueue(graph, node, edge, frags, num_frags);
		sent += num_frags;
	}

	return sent;
}

static int ip_fragment_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct ip_fragment_trace_data *t = data;
	return snprintf(
		buf,
		len,
		"id=%u frag=%u offset=%u%s",
		t->packet_id,
		t->frag_num,
		t->offset,
		t->more_frags ? " MF" : ""
	);
}

static struct rte_node_register fragment_node = {
	.name = "ip_fragment",
	.process = ip_fragment_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_OUTPUT] = "ip_output",
		[NO_MBUF] = "error_no_headroom",
		[ALREADY_FRAGMENTED] = "ip_fragment_already_fragmented",
		[ERROR] = "ip_fragment_error",
		[TOO_MANY_FRAGMENTS] = "ip_fragment_too_many_fragments",
	},
};

static struct gr_node_info info = {
	.node = &fragment_node,
	.type = GR_NODE_T_L3,
	.trace_format = ip_fragment_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip_fragment_error);
GR_DROP_REGISTER(ip_fragment_already_fragmented);
GR_DROP_REGISTER(ip_fragment_too_many_fragments);
