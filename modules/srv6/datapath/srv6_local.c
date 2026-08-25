// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include "eth.h"
#include "flow_hash.h"
#include "graph.h"
#include "ip6_datapath.h"
#include "l3.h"
#include "mbuf.h"
#include "nexthop.h"
#include "srv6.h"

#include <gr_infra.h>

//
// references are to rfc8986
//

enum {
	IP_INPUT = 0,
	IP6_INPUT,
	IP6_FORWARD,
	IP6_LOCAL,
	INVALID_PACKET,
	UNEXPECTED_UPPER,
	NOT_ALLOWED_UPPER,
	NO_TRANSIT,
	DEST_UNREACH,
	EDGE_COUNT,
};

struct trace_srv6_data {
	gr_srv6_behavior_t behavior;
	uint8_t segleft;
	uint16_t out_vrf_id;
};

struct ip6_info {
	uint16_t ext_offset;
	uint16_t sr_len;
	uint8_t proto;
	uint8_t *sr_prev_nh;
	struct rte_ipv6_hdr *ip6_hdr;
	struct rte_ipv6_routing_ext *sr;
};

static const uint8_t is_ipv6_ext[256] = {
	[IPPROTO_HOPOPTS] = 1,
	[IPPROTO_ROUTING] = 1,
	[IPPROTO_FRAGMENT] = 1,
	[IPPROTO_AH] = 1,
	[IPPROTO_DSTOPTS] = 1,
};

// stop_sr stops the walk on the first routing header instead of running to the ULP.
static int walk_ext_headers(struct rte_mbuf *m, struct ip6_info *ip6_info, bool stop_sr) {
	uint16_t data_len = rte_pktmbuf_data_len(m);

	// advance through IPv6 extension headers
	do {
		size_t ext_len = 0;
		int next_proto;
		uint8_t *ext;

		// minimal precheck: rte_ipv6_get_next_ext() touches at most 2 bytes
		if (unlikely(ip6_info->ext_offset + 2 > data_len))
			return -1;

		ext = rte_pktmbuf_mtod_offset(m, uint8_t *, ip6_info->ext_offset);
		next_proto = rte_ipv6_get_next_ext(ext, ip6_info->proto, &ext_len);
		// is_ipv6_ext already checked current proto is a valid IPv6 extension
		assert(next_proto >= 0 && next_proto < 256);
		ip6_info->ext_offset += ext_len;

		if (stop_sr && ip6_info->proto == IPPROTO_ROUTING) {
			ip6_info->proto = (uint8_t)next_proto;
			ip6_info->sr = (struct rte_ipv6_routing_ext *)ext;
			ip6_info->sr_len = ext_len;
			break;
		}

		ip6_info->proto = (uint8_t)next_proto;
		// next header is always the first field of any extension.
		// only decap_srv6() reads it, to unlink the SRH.
		if (stop_sr)
			ip6_info->sr_prev_nh = ext;
	} while (is_ipv6_ext[ip6_info->proto]);

	if (unlikely(ip6_info->ext_offset > data_len))
		return -1;

	return 0;
}

// Stop on the SRH, filling in sr and sr_len, and track the next header field
// preceding it so that decap_srv6() can unlink it.
static inline int find_srh(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	// no IPv6 extension headers
	if (!is_ipv6_ext[ip6_info->proto])
		return 0;

	return walk_ext_headers(m, ip6_info, true);
}

// Run to the upper layer protocol, leaving sr and sr_prev_nh alone.
static inline int find_upper_layer(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	// no IPv6 extension headers
	if (!is_ipv6_ext[ip6_info->proto])
		return 0;

	return walk_ext_headers(m, ip6_info, false);
}

// On return, proto is the upper layer protocol only when sr is NULL.
static int ip6_parse_to_srh(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	struct rte_ipv6_hdr *ip6;

	// already checked by ip6_input_process
	assert(rte_pktmbuf_data_len(m) >= sizeof(struct rte_ipv6_hdr));
	ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
	ip6_info->ip6_hdr = ip6;

	ip6_info->proto = ip6->proto;
	ip6_info->sr_prev_nh = &ip6->proto;
	ip6_info->ext_offset = sizeof(*ip6);
	ip6_info->sr = NULL;
	ip6_info->sr_len = 0;

	if (find_srh(m, ip6_info) < 0)
		return -1;

	if (ip6_info->sr) {
		struct rte_ipv6_routing_ext *sr = ip6_info->sr;

		// hdr_len is in 8B units (excl. first 8B)
		// -> ext_len = 8 * (hdr_len + 1)
		// each segment is 16B = 2x8B
		// -> nsegs = hdr_len/2
		// -> last_entry < hdr_len/2
		if ((size_t)((sr->hdr_len + 1) << 3) != ip6_info->sr_len
		    || sr->last_entry > sr->hdr_len / 2 - 1
		    || sr->segments_left > sr->last_entry + 1
		    || sr->type != RTE_IPV6_SRCRT_TYPE_4) {
			// XXX send icmp parameter problem
			return -1;
		}
	}

	return 0;
}

static int trace_srv6_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_srv6_data *t = data;
	if (t->out_vrf_id != GR_VRF_ID_UNDEF)
		return snprintf(
			buf,
			len,
			"action=%s segleft=%d out_vrf=%d",
			gr_srv6_behavior_name(t->behavior),
			t->segleft,
			t->out_vrf_id
		);
	else
		return snprintf(
			buf,
			len,
			"action=%s segleft=%d",
			gr_srv6_behavior_name(t->behavior),
			t->segleft
		);
}

// The segment list is stored right after the SRH, in reverse order.
static inline struct rte_ipv6_addr srh_segment(const struct rte_ipv6_routing_ext *sr, uint8_t i) {
	return ((const struct rte_ipv6_addr *)(sr + 1))[i];
}

// Decap srv6 header
static inline void decap_srv6(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	struct rte_ipv6_routing_ext *sr = ip6_info->sr;
	struct rte_ipv6_hdr *ip6 = ip6_info->ip6_hdr;
	uint32_t adj_len;

	// set last sid as DA
	ip6->dst_addr = srh_segment(sr, 0);

	// 4.16.1 PSP
	// remove this SRH
	adj_len = ip6_info->sr_len;
	*ip6_info->sr_prev_nh = sr->next_hdr;
	memmove((void *)ip6 + adj_len, ip6, (void *)sr - (void *)ip6);
	rte_pktmbuf_adj(m, adj_len);
	ip6 = (void *)ip6 + adj_len;
	ip6->payload_len = rte_cpu_to_be_16(rte_be_to_cpu_16(ip6->payload_len) - adj_len);

	ip6_info->ip6_hdr = ip6;
	ip6_info->ext_offset -= adj_len;
	ip6_info->sr = NULL;
	ip6_info->sr_len = 0;
	ip6_info->sr_prev_nh = NULL;
}

// Remove ipv6 headers and extension
static inline void decap_outer(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	// remove ip6 hdr with its extension header
	rte_pktmbuf_adj(m, ip6_info->ext_offset);
	ip6_info->ext_offset = 0;
	ip6_info->ip6_hdr = NULL;
	ip6_info->sr = NULL;
	ip6_info->sr_len = 0;
}

// Steer the packet to the local SID output VRF, if it has one.
static inline bool set_out_vrf_iface(struct rte_mbuf *m, struct nexthop_info_srv6_local *sr_d) {
	const struct iface *iface;

	if (sr_d->out_vrf_id == GR_VRF_ID_UNDEF)
		return true;

	iface = get_vrf_iface(sr_d->out_vrf_id);
	if (iface == NULL)
		return false;

	mbuf_data(m)->iface = iface;
	return true;
}

//
// 4.1.1. Upper-Layer Header
//
// The USP flavor (4.16.2) is always enabled, by design.
//
static int process_upper_layer(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	if (ip6_info->sr) {
		decap_srv6(m, ip6_info);

		if (unlikely(find_upper_layer(m, ip6_info) < 0))
			return INVALID_PACKET;
	}

	// RFC 8996 : 4.1.1 Upper-Layer Header
	// Allowing the processing of specific Upper-Layer header types is
	// useful for Operations, Administration, and Maintenance (OAM).  As an
	// example, an operator might permit pinging of SIDs
	// XXX: make allowed ULPs configurable (bitmap/flags).
	if (ip6_info->proto != IPPROTO_ICMPV6)
		// Optionally send ICMP Parameter Problem, Code 4, pointer = ip6_info->ext_offsets
		return NOT_ALLOWED_UPPER;

	assert(ip6_info->ip6_hdr != NULL);
	return IP6_LOCAL;
}

//
// Decapsulation behaviors
//
static int process_behav_decap(
	struct rte_mbuf *m,
	struct nexthop_info_srv6_local *sr_d,
	struct ip6_info *ip6_info
) {
	struct rte_ipv6_routing_ext *sr = ip6_info->sr;
	struct eth_input_mbuf_data *id;
	uint32_t flow_label;
	rte_edge_t edge;

	// transit is not allowed
	if (sr != NULL && sr->segments_left > 0)
		return NO_TRANSIT;

	// ip6_parse_to_srh() stopped on the SRH, resolve the real upper layer
	if (unlikely(find_upper_layer(m, ip6_info) < 0))
		return INVALID_PACKET;

	switch (ip6_info->proto) {
	case IPPROTO_IPV6:
		if (sr_d->behavior == SR_BEHAVIOR_END_DT4)
			return UNEXPECTED_UPPER;
		edge = IP6_INPUT;
		break;

	case IPPROTO_IPIP:
		if (sr_d->behavior == SR_BEHAVIOR_END_DT6)
			return UNEXPECTED_UPPER;
		edge = IP_INPUT;
		break;

	default:
		return process_upper_layer(m, ip6_info);
	}

	// Use the outer flow label as the exposed flow's entropy when the
	// encapsulating node filled it in (RFC 6438). A zero label carries
	// no entropy: drop the outer hash instead so the first consumer
	// hashes the inner packet.
	flow_label = rte_be_to_cpu_32(ip6_info->ip6_hdr->vtc_flow) & RTE_IPV6_HDR_FL_MASK;
	if (flow_label != 0)
		gr_mbuf_flow_hash_set(m, flow_label);
	else
		gr_mbuf_flow_hash_invalidate(m);

	// remove tunnel ipv6 + ext headers
	decap_outer(m, ip6_info);

	// The hw checksum offload only works on the outer IP.
	// Clear the offload flag so that ip_input will check it in software.
	m->ol_flags |= RTE_MBUF_F_RX_IP_CKSUM_NONE;

	if (!set_out_vrf_iface(m, sr_d))
		return DEST_UNREACH;

	// 4.16.3 USD: End.X hands the exposed packet to its L3 adjacency instead
	// of looking it up. The input node still validates the exposed header.
	id = eth_input_mbuf_data(m);
	id->nh = NULL;
	if (sr_d->behavior == SR_BEHAVIOR_END_X) {
		if (sr_d->l3_nh == NULL)
			return DEST_UNREACH;
		id->nh = sr_d->l3_nh;
	}

	id->domain = ETH_DOMAIN_LOCAL;

	return edge;
}

//
// Compressed SID shift-and-lookup (RFC 9800, Section 4.1.1).
//
// A CSID container packs multiple compressed SIDs after the locator block:
//
//   |<-- block -->|<-- csid -->|<--- argument (remaining csids) --->|
//   0             ^            ^                                    15
//             block_end      arg_off
//
// If the argument portion is non-zero, shift it left into the active CSID
// position and zero the vacated tail. This exposes the next CSID in the
// container as the new destination for FIB lookup. E.g.:
//
//   Before:  fd00:0202 : 0300 : 0100 : 0000 : 0000 : 0000 : 0000
//               block    csid  ~~~~ argument (next csid) ~~~~~~~
//
//   After:   fd00:0202 : 0100 : 0000 : 0000 : 0000 : 0000 : 0000
//               block    csid  ~~~~~~~~ zeroed tail ~~~~~~~~~~~~
//
// Returns true if the shift was performed, false if the container is exhausted
// (argument is all zeros, fall through to standard End).
//
static inline bool csid_shift(struct rte_ipv6_addr *da, uint8_t block_bits, uint8_t csid_bits) {
	uint8_t block_end = block_bits / CHAR_BIT;
	uint8_t csid_len = csid_bits / CHAR_BIT;
	uint8_t arg_off = block_end + csid_len;
	uint8_t arg = 0;

	assert(arg_off <= ARRAY_DIM(da->a));

	for (uint8_t i = arg_off; i < ARRAY_DIM(da->a); i++)
		arg |= da->a[i];
	if (arg == 0)
		return false; // argument portion is all zeros

	// shift argument left into the active CSID position
	memmove(&da->a[block_end], &da->a[arg_off], ARRAY_DIM(da->a) - arg_off);
	// zero the vacated tail
	memset(&da->a[ARRAY_DIM(da->a) - csid_len], 0, csid_len);

	return true;
}

//
// End/End.X behavior (RFC 8986 Section 4.1 and 4.10)
// END.X hands the packet to its configured L3 nexthop, END does a FIB lookup.
//
static int process_behav_end(
	struct rte_mbuf *m,
	struct nexthop_info_srv6_local *sr_d,
	struct ip6_info *ip6_info
) {
	struct rte_ipv6_routing_ext *sr = ip6_info->sr;
	struct eth_input_mbuf_data *id;

	// NEXT-CSID processing (RFC 9800)
	if (sr_d->flags & GR_SR_FL_FLAVOR_NEXT_CSID) {
		struct rte_ipv6_hdr *ip6 = ip6_info->ip6_hdr;

		if (csid_shift(&ip6->dst_addr, sr_d->block_bits, sr_d->csid_bits))
			goto forward;
		// container exhausted, fall through to standard End
	}

	// at the end of the tunnel
	if (sr == NULL || sr->segments_left == 0) {
		// 4.16.3 USD
		// this packet could be decapsulated and forwarded
		if (sr_d->flags & GR_SR_FL_FLAVOR_USD)
			return process_behav_decap(m, sr_d, ip6_info);

		// process locally
		return process_upper_layer(m, ip6_info);
	}

	// transit
	if (sr->segments_left == 1 && (sr_d->flags & GR_SR_FL_FLAVOR_PSP)) {
		decap_srv6(m, ip6_info);
	} else {
		struct rte_ipv6_hdr *ip6 = ip6_info->ip6_hdr;

		// use next sid in list
		--sr->segments_left;
		ip6->dst_addr = srh_segment(sr, sr->segments_left);
	}

forward:
	if (!set_out_vrf_iface(m, sr_d))
		return DEST_UNREACH;

	// END.X: set explicit nexthop and go directly to ip6_forward (bypass FIB lookup)
	if (sr_d->behavior == SR_BEHAVIOR_END_X) {
		if (sr_d->l3_nh == NULL)
			return DEST_UNREACH;
		l3_mbuf_data(m)->nh = sr_d->l3_nh;
		return IP6_FORWARD;
	}

	// END: go to ip6_input for FIB lookup
	id = eth_input_mbuf_data(m);
	id->domain = ETH_DOMAIN_LOCAL;
	id->nh = NULL;
	return IP6_INPUT;
}

static inline rte_edge_t srv6_local_process_pkt(
	struct rte_mbuf *m,
	struct nexthop_info_srv6_local *sr_d,
	struct ip6_info *ip6_info
) {
	switch (sr_d->behavior) {
	case SR_BEHAVIOR_END:
	case SR_BEHAVIOR_END_T:
	case SR_BEHAVIOR_END_X:
		return process_behav_end(m, sr_d, ip6_info);

	case SR_BEHAVIOR_END_DT4:
	case SR_BEHAVIOR_END_DT6:
	case SR_BEHAVIOR_END_DT46:
		return process_behav_decap(m, sr_d, ip6_info);

	default:
		return INVALID_PACKET;
	}
}

// called from 'ip6_input' node
static uint16_t
srv6_local_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct nexthop_info_srv6_local *sr_d;
	struct ip6_info ip6_info;
	struct rte_mbuf *m;
	rte_edge_t edge;
	int ret;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		ret = ip6_parse_to_srh(m, &ip6_info);
		if (ret < 0) {
			edge = INVALID_PACKET;
			goto next;
		}

		sr_d = nexthop_info_srv6_local(l3_mbuf_data(m)->nh);

		if (gr_mbuf_is_traced(m)) {
			struct trace_srv6_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->behavior = sr_d->behavior;
			t->out_vrf_id = sr_d->out_vrf_id;
			t->segleft = ip6_info.sr ? ip6_info.sr->segments_left : 0;
		}

		edge = srv6_local_process_pkt(m, sr_d, &ip6_info);

next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void srv6_node_init(void) {
	ip6_input_register_nexthop_type(GR_NH_T_SR6_LOCAL, "sr6_local");
}

static struct rte_node_register srv6_local_node = {
	.name = "sr6_local",

	.process = srv6_local_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IP_INPUT] = "ip_input",
		[IP6_INPUT] = "ip6_input",
		[IP6_FORWARD] = "ip6_forward",
		[IP6_LOCAL] = "ip6_input_local",
		[INVALID_PACKET] = "sr6_local_invalid",
		[UNEXPECTED_UPPER] = "sr6_local_unexpected_upper",
		[NOT_ALLOWED_UPPER] = "sr6_local_not_allowed_upper",
		[NO_TRANSIT] = "sr6_local_no_transit",
		[DEST_UNREACH] = "ip6_error_dest_unreach",
	},
};

static struct gr_node_info srv6_local_info = {
	.node = &srv6_local_node,
	.type = GR_NODE_T_L3,
	.trace_format = trace_srv6_format,
	.register_callback = srv6_node_init,
};

GR_NODE_REGISTER(srv6_local_info);

GR_DROP_REGISTER(sr6_local_invalid);
GR_DROP_REGISTER(sr6_local_unexpected_upper);
GR_DROP_REGISTER(sr6_local_not_allowed_upper);
GR_DROP_REGISTER(sr6_local_no_transit);

#ifdef __GROUT_UNIT_TEST__
#include "_cmocka.h"

struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);

mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(void, ip6_input_register_nexthop_type(gr_nh_type_t, const char *));
mock_func(struct iface *, get_vrf_iface(uint16_t));

struct ipv6_ext_hdr {
	uint8_t next_hdr;
	uint8_t hdr_ext_len; // in 8-octet units, not including first 8 bytes
	uint8_t options[6]; // hdr_ext_len == 0 still means 8 octets on the wire
} __attribute__((packed));

struct fake_mbuf {
	union {
		struct rte_ipv6_hdr ip6; // always first.
		uint8_t data
			[sizeof(struct rte_ipv6_hdr) + sizeof(struct ipv6_ext_hdr) + // for hbh
			 sizeof(struct rte_ipv6_routing_ext) + sizeof(struct rte_ipv6_addr)
			 + // for sid0
			 sizeof(struct ipv6_ext_hdr) + // for dstopts
			 sizeof(struct rte_ipv6_hdr)]; // for the inner packet
	};
	struct rte_mbuf mbuf;
	uint8_t priv[GR_MBUF_PRIV_MAX_SIZE]; // rte_mbuf_to_priv() lands here
	uint16_t offset;
	uint8_t *prev_next; // points inside data[] to the previous "Next Header" byte
};

static inline void fm_update_lengths(struct fake_mbuf *fm) {
	struct rte_ipv6_hdr *ip6 = &fm->ip6;
	uint16_t total = fm->offset;
	uint16_t pl;

	pl = total - sizeof(struct rte_ipv6_hdr);
	ip6->payload_len = rte_cpu_to_be_16(pl);
	fm->mbuf.data_len = total;
	fm->mbuf.pkt_len = total;
}

#define IP6_SRC ((struct rte_ipv6_addr)RTE_IPV6(0, 3, 0, 3, 1, 9, 8, 8))
#define IP6_DST ((struct rte_ipv6_addr)RTE_IPV6(0, 3, 0, 5, 2, 0, 2, 4))

static void fm_init_ipv6(struct fake_mbuf *fm, struct ip6_info *expect) {
	struct rte_ipv6_hdr *ip6 = &fm->ip6;

	memset(fm, 0, sizeof(struct fake_mbuf));
	memset(expect, 0, sizeof(struct ip6_info));

	ip6->vtc_flow = rte_cpu_to_be_32(6u << 28);
	ip6->proto = IPPROTO_NONE;
	ip6->src_addr = IP6_SRC;
	ip6->dst_addr = IP6_DST;

	fm->offset = sizeof(struct rte_ipv6_hdr);
	fm->prev_next = &ip6->proto;

	fm->mbuf.buf_addr = fm->data;
	fm->mbuf.packet_type = RTE_PTYPE_L3_IPV6;
	fm->mbuf.next = NULL;
	fm->mbuf.ol_flags = 0;

	fm_update_lengths(fm);

	expect->ext_offset = sizeof(struct rte_ipv6_hdr);
	expect->proto = IPPROTO_NONE;
	expect->sr_prev_nh = &ip6->proto;
	expect->ip6_hdr = ip6;
	expect->sr = NULL;
	expect->sr_len = 0;
}

// Generic 8n-byte extension (HbH/Dst-Opts).
static void push_ext8(
	struct fake_mbuf *fm,
	struct ip6_info *expect,
	uint8_t proto_value,
	uint16_t bytes,
	bool after_srh
) {
	uint8_t *p = fm->data + fm->offset;
	struct ipv6_ext_hdr *b = (struct ipv6_ext_hdr *)p;

	memset(p, 0, bytes);
	*fm->prev_next = proto_value;
	b->next_hdr = IPPROTO_NONE;
	b->hdr_ext_len = (uint8_t)((bytes / 8) - 1);

	fm->offset += bytes;
	fm->prev_next = &b->next_hdr;
	fm_update_lengths(fm);

	if (!after_srh) {
		expect->ext_offset += 8;
		expect->sr_prev_nh = fm->prev_next;
	} else
		expect->proto = proto_value;
}

// SRH with one SID
static void push_srh_1sid(struct fake_mbuf *fm, struct ip6_info *expect) {
	struct rte_ipv6_routing_ext *sr;
	struct rte_ipv6_addr *sid0;
	uint16_t srh_bytes;
	uint8_t *p;

	p = fm->data + fm->offset;
	*fm->prev_next = IPPROTO_ROUTING;

	sr = (struct rte_ipv6_routing_ext *)p;
	memset(sr, 0, sizeof *sr);

	srh_bytes = sizeof(struct rte_ipv6_routing_ext) + sizeof(struct rte_ipv6_addr);
	sr->type = RTE_IPV6_SRCRT_TYPE_4;
	sr->segments_left = 0;
	sr->last_entry = 0;
	sr->next_hdr = IPPROTO_NONE;
	sr->hdr_len = (uint8_t)((srh_bytes / 8) - 1);

	sid0 = (struct rte_ipv6_addr *)(p + sizeof(struct rte_ipv6_routing_ext));
	*sid0 = ((struct rte_ipv6_addr)RTE_IPV6(0, 3, 0, 1, 1, 9, 8, 6));

	fm->offset += srh_bytes;
	fm->prev_next = &sr->next_hdr;
	fm_update_lengths(fm);

	expect->sr = sr;
	expect->sr_len = srh_bytes;
	expect->ext_offset += srh_bytes;
}

// Inner IPv4 packet, header only.
static void push_inner_ipv4(struct fake_mbuf *fm) {
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(fm->data + fm->offset);

	*fm->prev_next = IPPROTO_IPIP;
	memset(ip, 0, sizeof(*ip));
	ip->version_ihl = RTE_IPV4_VHL_DEF;
	ip->total_length = rte_cpu_to_be_16(sizeof(*ip));
	ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_ICMP;
	ip->src_addr = RTE_IPV4(10, 0, 0, 1);
	ip->dst_addr = RTE_IPV4(10, 0, 0, 2);
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	fm->offset += sizeof(*ip);
	fm_update_lengths(fm);
}

// Inner IPv6 packet, header only.
static void push_inner_ipv6(struct fake_mbuf *fm) {
	struct rte_ipv6_hdr *ip = (struct rte_ipv6_hdr *)(fm->data + fm->offset);

	*fm->prev_next = IPPROTO_IPV6;
	memset(ip, 0, sizeof(*ip));
	ip->vtc_flow = rte_cpu_to_be_32(6u << 28);
	ip->proto = IPPROTO_ICMPV6;
	ip->hop_limits = 64;
	ip->src_addr = IP6_SRC;
	ip->dst_addr = IP6_DST;

	fm->offset += sizeof(*ip);
	fm_update_lengths(fm);
}

// Compare every field of ip6_info using only cmocka assert_ macros.
static inline void assert_ip6_info_equal(const struct ip6_info *got, const struct ip6_info *exp) {
	assert_non_null(got);
	assert_non_null(exp);

	// Scalars
	assert_int_equal(got->ext_offset, exp->ext_offset);
	assert_int_equal(got->sr_len, exp->sr_len);
	assert_int_equal(got->proto, exp->proto);

	// Pointers
	assert_ptr_equal(got->sr_prev_nh, exp->sr_prev_nh);
	assert_ptr_equal(got->ip6_hdr, exp->ip6_hdr);
	assert_ptr_equal(got->sr, exp->sr);
}

static void srv6_parse_only_ipv6(void **) {
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);
}

static void srv6_parse_ipv6_srv6(void **) {
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_srh_1sid(&fm, &expect);

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);

	assert_int_equal(find_upper_layer(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);
}

static void srv6_parse_ipv6_hop_srv6(void **) {
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_ext8(&fm, &expect, IPPROTO_HOPOPTS, sizeof(struct ipv6_ext_hdr), false);
	push_srh_1sid(&fm, &expect);

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);

	assert_int_equal(find_upper_layer(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);
}

static void srv6_parse_ipv6_srv6_dop(void **) {
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_srh_1sid(&fm, &expect);
	push_ext8(&fm, &expect, IPPROTO_DSTOPTS, sizeof(struct ipv6_ext_hdr), true);

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);

	// sr_prev_nh must still point before the SRH
	expect.ext_offset += 8;
	expect.proto = IPPROTO_NONE;

	assert_int_equal(find_upper_layer(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);
}

static void srv6_parse_ipv6_hop_srv6_dop(void **) {
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_ext8(&fm, &expect, IPPROTO_HOPOPTS, sizeof(struct ipv6_ext_hdr), false);
	push_srh_1sid(&fm, &expect);
	push_ext8(&fm, &expect, IPPROTO_DSTOPTS, sizeof(struct ipv6_ext_hdr), true);

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);

	// sr_prev_nh must still point before the SRH
	expect.ext_offset += 8;
	expect.proto = IPPROTO_NONE;

	assert_int_equal(find_upper_layer(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);
}

// End.DT4 with the inner packet sitting behind a destination options header.
static void srv6_decap_dt4_behind_dop(void **) {
	struct nexthop_info_srv6_local sr_d = {
		.base = {.behavior = SR_BEHAVIOR_END_DT4, .out_vrf_id = GR_VRF_ID_UNDEF},
	};
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_srh_1sid(&fm, &expect);
	push_ext8(&fm, &expect, IPPROTO_DSTOPTS, sizeof(struct ipv6_ext_hdr), true);
	*fm.prev_next = IPPROTO_IPIP;

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_int_equal(process_behav_decap(&fm.mbuf, &sr_d, &info), IP_INPUT);
	// the whole outer encapsulation must be gone, not just up to the SRH
	assert_int_equal(fm.mbuf.data_len, 0);
}

// Decap must leave a coherent flow hash: a non-zero outer flow label
// becomes the hash, a zero label invalidates any stale outer RSS value.
static void srv6_decap_flow_hash(void **) {
	struct nexthop_info_srv6_local sr_d = {
		.base = {.behavior = SR_BEHAVIOR_END_DT4, .out_vrf_id = GR_VRF_ID_UNDEF},
	};
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	// zero flow label: the stale outer hardware hash must be dropped
	fm_init_ipv6(&fm, &expect);
	push_srh_1sid(&fm, &expect);
	*fm.prev_next = IPPROTO_IPIP;
	fm.mbuf.hash.rss = 0xdeadbeef;
	fm.mbuf.ol_flags |= RTE_MBUF_F_RX_RSS_HASH;

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_int_equal(process_behav_decap(&fm.mbuf, &sr_d, &info), IP_INPUT);
	assert_false(gr_mbuf_flow_hash_is_valid(&fm.mbuf));

	// non-zero flow label: it becomes the flow hash
	memset(&info, 0, sizeof(info));
	fm_init_ipv6(&fm, &expect);
	fm.ip6.vtc_flow = rte_cpu_to_be_32((6u << 28) | 0xabcde);
	push_srh_1sid(&fm, &expect);
	*fm.prev_next = IPPROTO_IPIP;

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_int_equal(process_behav_decap(&fm.mbuf, &sr_d, &info), IP_INPUT);
	assert_true(gr_mbuf_flow_hash_is_valid(&fm.mbuf));
	assert_int_equal(fm.mbuf.hash.rss, 0xabcde);
}

// End.X with USD hands the exposed packet to the L3 adjacency instead of the
// FIB, but still lets the input node validate it.
static void srv6_end_x_usd(bool inner_v4, rte_edge_t expected_edge, uint16_t expected_len) {
	struct nexthop l3_nh = {0};
	struct nexthop_info_srv6_local sr_d = {
		.base = {
			.behavior = SR_BEHAVIOR_END_X,
			.out_vrf_id = GR_VRF_ID_UNDEF,
			.flags = GR_SR_FL_FLAVOR_USD,
		},
		.l3_nh = &l3_nh,
	};
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_srh_1sid(&fm, &expect);
	if (inner_v4)
		push_inner_ipv4(&fm);
	else
		push_inner_ipv6(&fm);

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_int_equal(process_behav_end(&fm.mbuf, &sr_d, &info), expected_edge);
	assert_ptr_equal(eth_input_mbuf_data(&fm.mbuf)->nh, &l3_nh);
	assert_int_equal(eth_input_mbuf_data(&fm.mbuf)->domain, ETH_DOMAIN_LOCAL);
	// only the inner packet is left, the input node validates it
	assert_int_equal(fm.mbuf.data_len, expected_len);
}

static void srv6_end_x_usd_inner_ipv4(void **) {
	srv6_end_x_usd(true, IP_INPUT, sizeof(struct rte_ipv4_hdr));
}

static void srv6_end_x_usd_inner_ipv6(void **) {
	srv6_end_x_usd(false, IP6_INPUT, sizeof(struct rte_ipv6_hdr));
}

// A SID announcing an inner packet that is not there must still reach the input
// node, which is the only place that rejects it.
static void srv6_end_x_usd_no_inner(void **) {
	struct nexthop l3_nh = {0};
	struct nexthop_info_srv6_local sr_d = {
		.base = {
			.behavior = SR_BEHAVIOR_END_X,
			.out_vrf_id = GR_VRF_ID_UNDEF,
			.flags = GR_SR_FL_FLAVOR_USD,
		},
		.l3_nh = &l3_nh,
	};
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_srh_1sid(&fm, &expect);
	*fm.prev_next = IPPROTO_IPIP;

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_int_equal(process_behav_end(&fm.mbuf, &sr_d, &info), IP_INPUT);
	assert_int_equal(fm.mbuf.data_len, 0);
}

// A container packing the active CSID 0100 and a trailing 0200, with the
// default 32 bit locator block and 16 bit CSIDs.
#define CSID_CONTAINER ((struct rte_ipv6_addr)RTE_IPV6(0x5f00, 0x102, 0x100, 0x200, 0, 0, 0, 0))

// uN: the shifted container goes back to the FIB.
static void srv6_end_next_csid(void **) {
	struct nexthop stale_nh = {0};
	struct nexthop_info_srv6_local sr_d = {
		.base = {
			.behavior = SR_BEHAVIOR_END,
			.out_vrf_id = GR_VRF_ID_UNDEF,
			.flags = GR_SR_FL_FLAVOR_NEXT_CSID,
			.block_bits = 32,
			.csid_bits = 16
		},
	};
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	fm.ip6.dst_addr = CSID_CONTAINER;
	// a previous packet in this mbuf may have left an adjacency behind
	eth_input_mbuf_data(&fm.mbuf)->nh = &stale_nh;

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_int_equal(process_behav_end(&fm.mbuf, &sr_d, &info), IP6_INPUT);
	assert_int_equal(eth_input_mbuf_data(&fm.mbuf)->domain, ETH_DOMAIN_LOCAL);
	// ip6_input must look the shifted container up, not reuse the stale one
	assert_null(eth_input_mbuf_data(&fm.mbuf)->nh);
	// 0100 consumed, 0200 is now the active CSID
	assert_int_equal(fm.ip6.dst_addr.a[4], 0x02);
	assert_int_equal(fm.ip6.dst_addr.a[5], 0x00);
}

// uA: the shifted container goes to the configured L3 nexthop.
static void srv6_end_x_next_csid(void **) {
	struct nexthop l3_nh = {0};
	struct nexthop_info_srv6_local sr_d = {
		.base = {
			.behavior = SR_BEHAVIOR_END_X,
			.out_vrf_id = GR_VRF_ID_UNDEF,
			.flags = GR_SR_FL_FLAVOR_NEXT_CSID,
			.block_bits = 32,
			.csid_bits = 16,
		},
		.l3_nh = &l3_nh,
	};
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	fm.ip6.dst_addr = CSID_CONTAINER;

	assert_int_equal(ip6_parse_to_srh(&fm.mbuf, &info), 0);
	assert_int_equal(process_behav_end(&fm.mbuf, &sr_d, &info), IP6_FORWARD);
	assert_ptr_equal(l3_mbuf_data(&fm.mbuf)->nh, &l3_nh);
	assert_int_equal(fm.ip6.dst_addr.a[4], 0x02);
	assert_int_equal(fm.ip6.dst_addr.a[5], 0x00);
}

// ---- runner -----------------------------------------------------------------
int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(srv6_parse_only_ipv6),
		cmocka_unit_test(srv6_parse_ipv6_srv6),
		cmocka_unit_test(srv6_parse_ipv6_hop_srv6),
		cmocka_unit_test(srv6_parse_ipv6_srv6_dop),
		cmocka_unit_test(srv6_parse_ipv6_hop_srv6_dop),
		cmocka_unit_test(srv6_decap_dt4_behind_dop),
		cmocka_unit_test(srv6_decap_flow_hash),
		cmocka_unit_test(srv6_end_x_usd_inner_ipv4),
		cmocka_unit_test(srv6_end_x_usd_inner_ipv6),
		cmocka_unit_test(srv6_end_x_usd_no_inner),
		cmocka_unit_test(srv6_end_next_csid),
		cmocka_unit_test(srv6_end_x_next_csid),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif
