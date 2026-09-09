// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Maxime Leroy

#include "_cmocka.h"
#include "flow_hash.h"

#include <netinet/in.h>
#include <string.h>

// Large enough for an IPv6 header followed by an L4 header.
struct fake_mbuf {
	uint8_t buf[128];
	struct rte_mbuf mbuf;
};

static void fm_init(struct fake_mbuf *fm, uint16_t len) {
	memset(fm, 0, sizeof(*fm));
	fm->mbuf.buf_addr = fm->buf;
	fm->mbuf.data_len = len;
	fm->mbuf.pkt_len = len;
	fm->mbuf.nb_segs = 1;
}

// Both rte_tcp_hdr and rte_udp_hdr start with the two ports.
static void fm_set_ports(struct fake_mbuf *fm, size_t l3_len) {
	struct rte_tcp_hdr *l4 = (struct rte_tcp_hdr *)(fm->buf + l3_len);

	l4->src_port = rte_cpu_to_be_16(45678);
	l4->dst_port = rte_cpu_to_be_16(179);
}

static void fm_init_ip4(struct fake_mbuf *fm, uint8_t proto, rte_be16_t frag_offset) {
	struct rte_ipv4_hdr *ip;

	fm_init(fm, sizeof(*ip) + sizeof(struct rte_tcp_hdr));

	ip = (struct rte_ipv4_hdr *)fm->buf;
	ip->version = 4;
	ip->ihl = sizeof(*ip) / 4;
	ip->total_length = rte_cpu_to_be_16(fm->mbuf.pkt_len);
	ip->time_to_live = 64;
	ip->next_proto_id = proto;
	ip->fragment_offset = frag_offset;
	ip->src_addr = RTE_IPV4(192, 168, 0, 1);
	ip->dst_addr = RTE_IPV4(192, 168, 0, 2);

	fm_set_ports(fm, sizeof(*ip));
}

static void fm_init_ip6(struct fake_mbuf *fm, uint8_t proto) {
	struct rte_ipv6_hdr *ip;

	fm_init(fm, sizeof(*ip) + sizeof(struct rte_tcp_hdr));

	ip = (struct rte_ipv6_hdr *)fm->buf;
	ip->vtc_flow = rte_cpu_to_be_32(6 << 28);
	ip->payload_len = rte_cpu_to_be_16(sizeof(struct rte_tcp_hdr));
	ip->proto = proto;
	ip->hop_limits = 64;
	memset(&ip->src_addr, 0x11, sizeof(ip->src_addr));
	memset(&ip->dst_addr, 0x22, sizeof(ip->dst_addr));

	fm_set_ports(fm, sizeof(*ip));
}

static uint32_t hash_of(struct fake_mbuf *fm, rte_be16_t eth_type) {
	uint32_t hash = 0;

	assert_true(flow_hash_l3l4(&fm->mbuf, 0, eth_type, &hash));

	return hash;
}

static uint32_t hash4_of(struct fake_mbuf *fm) {
	return hash_of(fm, RTE_BE16(RTE_ETHER_TYPE_IPV4));
}

static uint32_t hash6_of(struct fake_mbuf *fm) {
	return hash_of(fm, RTE_BE16(RTE_ETHER_TYPE_IPV6));
}

// The don't fragment flag shares the field with the fragment offset. Setting it
// must not make the packet look like a fragment and cost it its L4 ports.
static void df_hashes_like_no_df(uint8_t proto) {
	struct fake_mbuf fm;
	uint32_t plain, df;

	fm_init_ip4(&fm, proto, 0);
	plain = hash4_of(&fm);

	fm_init_ip4(&fm, proto, RTE_BE16(RTE_IPV4_HDR_DF_FLAG));
	df = hash4_of(&fm);

	assert_int_equal(plain, df);
}

static void flow_hash_tcp_df(void **) {
	df_hashes_like_no_df(IPPROTO_TCP);
}

static void flow_hash_udp_df(void **) {
	df_hashes_like_no_df(IPPROTO_UDP);
}

// A real fragment still has its ports ignored, so its hash differs from the
// same packet sent unfragmented.
static void fragment_ignores_ports(rte_be16_t frag_offset) {
	struct fake_mbuf fm;
	uint32_t plain, frag;

	fm_init_ip4(&fm, IPPROTO_TCP, 0);
	plain = hash4_of(&fm);

	fm_init_ip4(&fm, IPPROTO_TCP, frag_offset);
	frag = hash4_of(&fm);

	assert_int_not_equal(plain, frag);
}

static void flow_hash_more_fragments(void **) {
	fragment_ignores_ports(RTE_BE16(RTE_IPV4_HDR_MF_FLAG));
}

static void flow_hash_fragment_offset(void **) {
	fragment_ignores_ports(rte_cpu_to_be_16(1480 / 8));
}

// A fragment with the don't fragment flag also set is still a fragment.
static void flow_hash_fragment_with_df(void **) {
	fragment_ignores_ports(RTE_BE16(RTE_IPV4_HDR_DF_FLAG | RTE_IPV4_HDR_MF_FLAG));
}

// A frame too short to hold the L3 header must be refused rather than read
// past the end of the segment.
static void flow_hash_runt_ipv4(void **) {
	struct fake_mbuf fm;
	uint32_t hash = 0;

	fm_init_ip4(&fm, IPPROTO_TCP, 0);
	fm.mbuf.data_len = sizeof(struct rte_ipv4_hdr) - 1;

	assert_false(flow_hash_l3l4(&fm.mbuf, 0, RTE_BE16(RTE_ETHER_TYPE_IPV4), &hash));
}

static void flow_hash_runt_ipv6(void **) {
	struct fake_mbuf fm;
	uint32_t hash = 0;

	fm_init_ip6(&fm, IPPROTO_TCP);
	fm.mbuf.data_len = sizeof(struct rte_ipv6_hdr) - 1;

	assert_false(flow_hash_l3l4(&fm.mbuf, 0, RTE_BE16(RTE_ETHER_TYPE_IPV6), &hash));
}

static void flow_hash_l3_offset_past_end(void **) {
	struct fake_mbuf fm;
	uint32_t hash = 0;

	fm_init_ip4(&fm, IPPROTO_TCP, 0);

	assert_false(
		flow_hash_l3l4(&fm.mbuf, fm.mbuf.data_len + 1, RTE_BE16(RTE_ETHER_TYPE_IPV4), &hash)
	);
}

// L3 is complete but the ports are not. Hash the L3 tuple alone, exactly like
// a fragment, instead of reading whatever sits after the packet.
static void flow_hash_truncated_ports_ipv4(void **) {
	struct fake_mbuf fm;
	uint32_t frag, truncated;

	fm_init_ip4(&fm, IPPROTO_TCP, RTE_BE16(RTE_IPV4_HDR_MF_FLAG));
	frag = hash4_of(&fm);

	fm_init_ip4(&fm, IPPROTO_TCP, 0);
	fm.mbuf.data_len = sizeof(struct rte_ipv4_hdr);
	truncated = hash4_of(&fm);

	assert_int_equal(frag, truncated);
}

// Same on the IPv6 side, compared against a next header that carries no ports.
static void flow_hash_truncated_ports_ipv6(void **) {
	struct fake_mbuf fm;
	uint32_t no_ports, truncated;

	fm_init_ip6(&fm, IPPROTO_HOPOPTS);
	no_ports = hash6_of(&fm);

	fm_init_ip6(&fm, IPPROTO_TCP);
	fm.mbuf.data_len = sizeof(struct rte_ipv6_hdr);
	truncated = hash6_of(&fm);

	assert_int_equal(no_ports, truncated);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(flow_hash_tcp_df),
		cmocka_unit_test(flow_hash_udp_df),
		cmocka_unit_test(flow_hash_more_fragments),
		cmocka_unit_test(flow_hash_fragment_offset),
		cmocka_unit_test(flow_hash_fragment_with_df),
		cmocka_unit_test(flow_hash_runt_ipv4),
		cmocka_unit_test(flow_hash_runt_ipv6),
		cmocka_unit_test(flow_hash_l3_offset_past_end),
		cmocka_unit_test(flow_hash_truncated_ports_ipv4),
		cmocka_unit_test(flow_hash_truncated_ports_ipv6),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
