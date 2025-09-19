// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_srv6_nexthop.h>
#include <gr_trace.h>

//
// references are to rfc8986
//

enum {
	IP_INPUT = 0,
	IP6_INPUT,
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
	struct rte_ipv6_addr src;
	struct rte_ipv6_addr dst;
	uint16_t ext_offset;
	uint16_t sr_len;
	uint8_t proto;
	// Pointer to the Next Header byte in the previous header
	// (IPv6 base NH if SRH is first).
	uint8_t *p_proto;
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

static int __fetch_upper_layer(struct rte_mbuf *m, struct ip6_info *ip6_info, bool stop_sr) {
	uint16_t data_len = rte_pktmbuf_data_len(m);

	// advance through IPv6 extension headers
	do {
		size_t ext_len = 0;
		int next_proto;
		uint8_t *ext;

		// minimal precheck: rte_ipv6_get_next_ext() touches ≤ 2 bytes
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
		// next header is always the first field of any extension
		ip6_info->p_proto = ext;
	} while (is_ipv6_ext[ip6_info->proto]);

	// single final guard
	if (unlikely(ip6_info->ext_offset > data_len))
		return -1;

	return 0;
}

static inline int fetch_upper_layer(struct rte_mbuf *m, struct ip6_info *ip6_info, bool stop_sr) {
	// no IPv6 extension headers
	if (!is_ipv6_ext[ip6_info->proto])
		return 0;

	return __fetch_upper_layer(m, ip6_info, stop_sr);
}

static int ip6_fill_infos(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	struct rte_ipv6_hdr *ip6;

	// already checked by ip6_input_process
	assert(rte_pktmbuf_data_len(m) >= sizeof(struct rte_ipv6_hdr));
	ip6 = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
	ip6_info->ip6_hdr = ip6;

	ip6_info->src = ip6->src_addr;
	ip6_info->dst = ip6->dst_addr;
	ip6_info->proto = ip6->proto;
	ip6_info->p_proto = &ip6->proto;
	ip6_info->ext_offset = sizeof(*ip6);
	ip6_info->sr = NULL;
	ip6_info->sr_len = 0;

	if (fetch_upper_layer(m, ip6_info, true) < 0)
		return -1;

	if (ip6_info->sr) {
		struct rte_ipv6_routing_ext *sr = ip6_info->sr;

		// hdr_len is in 8B units (excl. first 8B)
		// -> ext_len = 8 * (hdr_len + 1)
		// each segment is 16B = 2×8B
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
	if (t->out_vrf_id < GR_MAX_VRFS)
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

// Decap srv6 header
static inline void decap_srv6(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	struct rte_ipv6_routing_ext *sr = ip6_info->sr;
	struct rte_ipv6_hdr *ip6 = ip6_info->ip6_hdr;
	uint32_t adj_len;

	// set last sid as DA
	ip6->dst_addr = ((struct rte_ipv6_addr *)(sr + 1))[0];

	// 4.16.1 PSP
	// remove this SRH
	adj_len = ip6_info->sr_len;
	*ip6_info->p_proto = sr->next_hdr;
	memmove((void *)ip6 + adj_len, ip6, (void *)sr - (void *)ip6);
	rte_pktmbuf_adj(m, adj_len);
	ip6 = (void *)ip6 + adj_len;
	ip6->payload_len = rte_cpu_to_be_16(rte_be_to_cpu_16(ip6->payload_len) - adj_len);

	// After decap_srv6
	ip6_info->ip6_hdr = ip6;
	ip6_info->ext_offset -= adj_len;
	ip6_info->sr = NULL;
	ip6_info->sr_len = 0;
	// ip6_info->p_proto is invalid, but not used
}

// Remove ipv6 headers and extension
static inline int decap_outer(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	if (fetch_upper_layer(m, ip6_info, false) < 0)
		return -1;

	// remove ip6 hdr with its extension header
	rte_pktmbuf_adj(m, ip6_info->ext_offset);
	ip6_info->ext_offset = 0;
	ip6_info->ip6_hdr = NULL;
	ip6_info->sr = NULL;
	ip6_info->sr_len = 0;
	return 0;
}

//
// 4.1.1. Upper-Layer Header
//
// The USP flavor (4.16.2) is always enabled, by design.
//
static int process_upper_layer(struct rte_mbuf *m, struct ip6_info *ip6_info) {
	if (ip6_info->sr) {
		decap_srv6(m, ip6_info);

		if (unlikely(fetch_upper_layer(m, ip6_info, false) < 0))
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
	const struct iface *iface;
	rte_edge_t edge;

	// transit is not allowed
	if (sr != NULL && sr->segments_left > 0)
		return NO_TRANSIT;

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

	// remove tunnel ipv6 + ext headers
	if (ip6_info->ext_offset && decap_outer(m, ip6_info) < 0)
		return INVALID_PACKET;

	id = eth_input_mbuf_data(m);
	id->domain = ETH_DOMAIN_LOCAL;
	if (sr_d->out_vrf_id < GR_MAX_VRFS) {
		iface = get_vrf_iface(sr_d->out_vrf_id);
		if (iface == NULL)
			return DEST_UNREACH;
		id->iface = iface;
	}

	return edge;
}

//
// End behavior
//
static int process_behav_end(
	struct rte_mbuf *m,
	struct nexthop_info_srv6_local *sr_d,
	struct ip6_info *ip6_info
) {
	struct rte_ipv6_routing_ext *sr = ip6_info->sr;
	const struct iface *iface;

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
		ip6->dst_addr = ((struct rte_ipv6_addr *)(sr + 1))[sr->segments_left];
	}

	// change input interface to the vrf we wish to go
	if (sr_d->out_vrf_id < GR_MAX_VRFS) {
		iface = get_vrf_iface(sr_d->out_vrf_id);
		if (iface == NULL)
			return DEST_UNREACH;
		mbuf_data(m)->iface = iface;
	}
	eth_input_mbuf_data(m)->domain = ETH_DOMAIN_LOCAL;

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
	struct trace_srv6_data *t;
	struct ip6_info ip6_info;
	struct rte_mbuf *m;
	rte_edge_t edge;
	int ret;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		ret = ip6_fill_infos(m, &ip6_info);
		if (ret < 0) {
			edge = INVALID_PACKET;
			goto next;
		}

		sr_d = nexthop_info_srv6_local(ip6_output_mbuf_data(m)->nh);

		if (gr_mbuf_is_traced(m)) {
			t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->behavior = sr_d->behavior;
			t->out_vrf_id = sr_d->out_vrf_id;
			t->segleft = ip6_info.sr ? ip6_info.sr->segments_left : 0;
		} else
			t = NULL;

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
	.trace_format = trace_srv6_format,
	.register_callback = srv6_node_init,
};

GR_NODE_REGISTER(srv6_local_info);

GR_DROP_REGISTER(sr6_local_invalid);
GR_DROP_REGISTER(sr6_local_unexpected_upper);
GR_DROP_REGISTER(sr6_local_not_allowed_upper);
GR_DROP_REGISTER(sr6_local_no_transit);

#ifdef __GROUT_UNIT_TEST__
#include <gr_cmocka.h>

int gr_rte_log_type;
struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);

mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(void, ip6_input_register_nexthop_type(gr_nh_type_t, const char *));
mock_func(struct iface *, get_vrf_iface(uint16_t));

struct ipv6_ext_base {
	uint8_t next_hdr;
	uint8_t hdr_ext_len; // in 8-octet units, not including first 8 bytes
} __attribute__((packed));

struct fake_mbuf {
	union {
		struct rte_ipv6_hdr ip6; // always first.
		uint8_t data
			[sizeof(struct rte_ipv6_hdr) + sizeof(struct ipv6_ext_base) + // for hbh
			 sizeof(struct rte_ipv6_routing_ext) + sizeof(struct rte_ipv6_addr)
			 + // for sid0
			 sizeof(struct ipv6_ext_base)]; // for dstopts
	};
	struct rte_mbuf mbuf;
	uint16_t offset;
	uint8_t *prev_next; // points inside data[] to the previous “Next Header” byte
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

	expect->src = IP6_SRC;
	expect->dst = IP6_DST;
	expect->ext_offset = sizeof(struct rte_ipv6_hdr);
	expect->proto = IPPROTO_NONE;
	expect->p_proto = &ip6->proto;
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
	struct ipv6_ext_base *b = (struct ipv6_ext_base *)p;

	memset(p, 0, bytes);
	*fm->prev_next = proto_value;
	b->next_hdr = IPPROTO_NONE;
	b->hdr_ext_len = (uint8_t)((bytes / 8) - 1);

	fm->offset += bytes;
	fm->prev_next = &b->next_hdr;
	fm_update_lengths(fm);

	if (!after_srh) {
		expect->ext_offset += 8;
		expect->p_proto = fm->prev_next;
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

static void assert_ipv6_equal(const struct rte_ipv6_addr *got, const struct rte_ipv6_addr *exp) {
	assert_non_null(got);
	assert_non_null(exp);
	assert_memory_equal(got, exp, sizeof(struct rte_ipv6_addr));
}

// Compare every field of ip6_info using only cmocka assert_ macros.
static inline void assert_ip6_info_equal(const struct ip6_info *got, const struct ip6_info *exp) {
	assert_non_null(got);
	assert_non_null(exp);

	// Addresses
	assert_ipv6_equal(&got->src, &exp->src);
	assert_ipv6_equal(&got->dst, &exp->dst);

	// Scalars
	assert_int_equal(got->ext_offset, exp->ext_offset);
	assert_int_equal(got->sr_len, exp->sr_len);
	assert_int_equal(got->proto, exp->proto);

	// Pointers
	assert_ptr_equal(got->p_proto, exp->p_proto);
	assert_ptr_equal(got->ip6_hdr, exp->ip6_hdr);
	assert_ptr_equal(got->sr, exp->sr);
}

static void srv6_parse_only_ipv6(void **) {
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	// no extensions added

	assert_int_equal(ip6_fill_infos(&fm.mbuf, &info), 0);
	assert_memory_equal(&info, &expect, sizeof info);
}

static void srv6_parse_ipv6_srv6(void **) {
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_srh_1sid(&fm, &expect);

	assert_int_equal(ip6_fill_infos(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);

	assert_int_equal(fetch_upper_layer(&fm.mbuf, &info, false), 0);
	assert_ip6_info_equal(&info, &expect);
}

static void srv6_parse_ipv6_hop_srv6(void **) {
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_ext8(&fm, &expect, IPPROTO_HOPOPTS, 8, false);
	push_srh_1sid(&fm, &expect);

	assert_int_equal(ip6_fill_infos(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);

	assert_int_equal(fetch_upper_layer(&fm.mbuf, &info, false), 0);
	assert_ip6_info_equal(&info, &expect);
}

static void srv6_parse_ipv6_srv6_dop(void **) {
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_srh_1sid(&fm, &expect);
	push_ext8(&fm, &expect, IPPROTO_DSTOPTS, 8, true);

	assert_int_equal(ip6_fill_infos(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);

	expect.ext_offset += 8;
	expect.p_proto = fm.prev_next;
	expect.proto = IPPROTO_NONE;

	assert_int_equal(fetch_upper_layer(&fm.mbuf, &info, false), 0);
	assert_ip6_info_equal(&info, &expect);
}

static void srv6_parse_ipv6_hop_srv6_dop(void **) {
	struct ip6_info info = {0}, expect;
	struct fake_mbuf fm;

	fm_init_ipv6(&fm, &expect);
	push_ext8(&fm, &expect, IPPROTO_HOPOPTS, 8, false);
	push_srh_1sid(&fm, &expect);
	push_ext8(&fm, &expect, IPPROTO_DSTOPTS, 8, true);

	assert_int_equal(ip6_fill_infos(&fm.mbuf, &info), 0);
	assert_ip6_info_equal(&info, &expect);

	expect.ext_offset += 8;
	expect.p_proto = fm.prev_next;
	expect.proto = IPPROTO_NONE;

	assert_int_equal(fetch_upper_layer(&fm.mbuf, &info, false), 0);
	assert_ip6_info_equal(&info, &expect);
}

// ---- runner -----------------------------------------------------------------
int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(srv6_parse_only_ipv6),
		cmocka_unit_test(srv6_parse_ipv6_srv6),
		cmocka_unit_test(srv6_parse_ipv6_hop_srv6),
		cmocka_unit_test(srv6_parse_ipv6_srv6_dop),
		cmocka_unit_test(srv6_parse_ipv6_hop_srv6_dop),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif
