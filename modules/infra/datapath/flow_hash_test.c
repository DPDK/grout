// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Harrison Caldicott
// Copyright (c) 2026 Maxime Leroy

#include "_cmocka.h"
#include "flow_hash.h"

#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_ip6.h>
#include <rte_udp.h>

#include <stddef.h>
#include <string.h>

struct test_packet {
	struct rte_mbuf mbuf;
	struct rte_ether_hdr eth;
	struct rte_ipv4_hdr ip;
	struct rte_udp_hdr udp;
};

struct test_packet6 {
	struct rte_mbuf mbuf;
	struct rte_ether_hdr eth;
	struct rte_ipv6_hdr ip;
	struct rte_udp_hdr udp;
};

static void packet_init(struct test_packet *p, rte_be16_t src_port) {
	memset(p, 0, sizeof(*p));
	p->mbuf.buf_addr = &p->eth;
	p->mbuf.data_len = sizeof(*p) - offsetof(struct test_packet, eth);
	p->mbuf.pkt_len = p->mbuf.data_len;
	p->eth.dst_addr = (struct rte_ether_addr) {{0x02, 0, 0, 0, 0, 2}};
	p->eth.src_addr = (struct rte_ether_addr) {{0x02, 0, 0, 0, 0, 1}};
	p->eth.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
	p->ip.version_ihl = RTE_IPV4_VHL_DEF;
	p->ip.fragment_offset = RTE_BE16(RTE_IPV4_HDR_DF_FLAG);
	p->ip.next_proto_id = IPPROTO_UDP;
	p->ip.src_addr = RTE_BE32(0x0a000001);
	p->ip.dst_addr = RTE_BE32(0x0a000002);
	p->udp.src_port = src_port;
	p->udp.dst_port = RTE_BE16(9000);
}

static void packet6_init(struct test_packet6 *p, rte_be16_t src_port) {
	memset(p, 0, sizeof(*p));
	p->mbuf.buf_addr = &p->eth;
	p->mbuf.data_len = sizeof(*p) - offsetof(struct test_packet6, eth);
	p->mbuf.pkt_len = p->mbuf.data_len;
	p->eth.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);
	p->ip.vtc_flow = RTE_BE32(6 << 28);
	p->ip.proto = IPPROTO_UDP;
	p->ip.src_addr = (struct rte_ipv6_addr)RTE_IPV6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
	p->ip.dst_addr = (struct rte_ipv6_addr)RTE_IPV6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
	p->udp.src_port = src_port;
	p->udp.dst_port = RTE_BE16(9000);
}

static void software_hash_is_stable_per_flow(void **) {
	struct test_packet a, b;

	packet_init(&a, RTE_BE16(20000));
	packet_init(&b, RTE_BE16(20000));
	assert_int_equal(
		gr_mbuf_flow_hash(&a.mbuf, GR_MBUF_FLOW_HASH_RSS),
		gr_mbuf_flow_hash(&b.mbuf, GR_MBUF_FLOW_HASH_RSS)
	);
}

static void software_hash_distinguishes_udp_flows(void **) {
	struct test_packet a, b;

	packet_init(&a, RTE_BE16(20000));
	packet_init(&b, RTE_BE16(20001));
	assert_int_not_equal(
		gr_mbuf_flow_hash(&a.mbuf, GR_MBUF_FLOW_HASH_RSS),
		gr_mbuf_flow_hash(&b.mbuf, GR_MBUF_FLOW_HASH_RSS)
	);
	assert_int_equal(
		gr_mbuf_flow_hash(&a.mbuf, GR_MBUF_FLOW_HASH_L2),
		gr_mbuf_flow_hash(&b.mbuf, GR_MBUF_FLOW_HASH_L2)
	);
}

static void hardware_rss_takes_precedence(void **) {
	struct test_packet p;

	packet_init(&p, RTE_BE16(20000));
	p.mbuf.ol_flags = RTE_MBUF_F_RX_RSS_HASH;
	p.mbuf.hash.rss = 0x12345678;
	assert_int_equal(gr_mbuf_flow_hash(&p.mbuf, GR_MBUF_FLOW_HASH_RSS), 0x12345678);
}

// The DF flag shares its field with the fragment offset. Setting it must not
// make the packet look like a fragment and cost it its L4 ports.
static void df_flag_keeps_the_ports(uint8_t proto) {
	struct test_packet plain, df;

	packet_init(&plain, RTE_BE16(20000));
	plain.ip.next_proto_id = proto;
	plain.ip.fragment_offset = 0;
	packet_init(&df, RTE_BE16(20000));
	df.ip.next_proto_id = proto;
	df.ip.fragment_offset = RTE_BE16(RTE_IPV4_HDR_DF_FLAG);

	assert_int_equal(
		gr_mbuf_flow_hash(&plain.mbuf, GR_MBUF_FLOW_HASH_RSS),
		gr_mbuf_flow_hash(&df.mbuf, GR_MBUF_FLOW_HASH_RSS)
	);
}

static void tcp_df_hashes_like_no_df(void **) {
	df_flag_keeps_the_ports(IPPROTO_TCP);
}

static void udp_df_hashes_like_no_df(void **) {
	df_flag_keeps_the_ports(IPPROTO_UDP);
}

// A real fragment has its ports ignored, so it hashes unlike the same packet
// sent whole, whatever else is set in the field.
static void fragment_ignores_ports(rte_be16_t fragment_offset) {
	struct test_packet whole, frag;

	packet_init(&whole, RTE_BE16(20000));
	whole.ip.next_proto_id = IPPROTO_TCP;
	whole.ip.fragment_offset = 0;
	packet_init(&frag, RTE_BE16(20000));
	frag.ip.next_proto_id = IPPROTO_TCP;
	frag.ip.fragment_offset = fragment_offset;

	assert_int_not_equal(
		gr_mbuf_flow_hash(&whole.mbuf, GR_MBUF_FLOW_HASH_RSS),
		gr_mbuf_flow_hash(&frag.mbuf, GR_MBUF_FLOW_HASH_RSS)
	);
}

static void first_fragment_ignores_ports(void **) {
	fragment_ignores_ports(RTE_BE16(RTE_IPV4_HDR_MF_FLAG));
}

static void later_fragment_ignores_ports(void **) {
	fragment_ignores_ports(rte_cpu_to_be_16(1480 / 8));
}

static void fragment_with_df_ignores_ports(void **) {
	fragment_ignores_ports(RTE_BE16(RTE_IPV4_HDR_DF_FLAG | RTE_IPV4_HDR_MF_FLAG));
}

// IPv6 keeps its ports behind the fragment header, if the fragment has any
// at all, so a fragment is hashed on addresses only like an IPv4 one.
static void ipv6_fragments_ignore_ports(void **) {
	struct test_packet6 whole, first, later;

	packet6_init(&whole, RTE_BE16(20000));
	packet6_init(&first, RTE_BE16(20000));
	first.ip.proto = IPPROTO_FRAGMENT;
	packet6_init(&later, RTE_BE16(20001));
	later.ip.proto = IPPROTO_FRAGMENT;

	assert_int_not_equal(
		gr_mbuf_flow_hash(&whole.mbuf, GR_MBUF_FLOW_HASH_RSS),
		gr_mbuf_flow_hash(&first.mbuf, GR_MBUF_FLOW_HASH_RSS)
	);
	assert_int_equal(
		gr_mbuf_flow_hash(&first.mbuf, GR_MBUF_FLOW_HASH_RSS),
		gr_mbuf_flow_hash(&later.mbuf, GR_MBUF_FLOW_HASH_RSS)
	);
}

static void ipv4_fragments_share_one_hash(void **) {
	struct test_packet first, later;

	packet_init(&first, RTE_BE16(20000));
	packet_init(&later, RTE_BE16(20001));
	first.ip.fragment_offset = RTE_BE16(RTE_IPV4_HDR_MF_FLAG);
	later.ip.fragment_offset = RTE_BE16(1);

	assert_int_equal(
		gr_mbuf_flow_hash(&first.mbuf, GR_MBUF_FLOW_HASH_RSS),
		gr_mbuf_flow_hash(&later.mbuf, GR_MBUF_FLOW_HASH_RSS)
	);
}

static void short_frames_hash_what_they_carry(void **) {
	struct test_packet full, no_l4, no_l3, frag;
	uint32_t l3_only;

	packet_init(&full, RTE_BE16(20000));
	packet_init(&frag, RTE_BE16(20000));
	frag.ip.fragment_offset = RTE_BE16(1);
	l3_only = gr_mbuf_flow_hash(&frag.mbuf, GR_MBUF_FLOW_HASH_RSS);
	assert_int_not_equal(gr_mbuf_flow_hash(&full.mbuf, GR_MBUF_FLOW_HASH_RSS), l3_only);

	// a frame cut inside the UDP ports is hashed on addresses only
	packet_init(&no_l4, RTE_BE16(20000));
	no_l4.mbuf.data_len = sizeof(no_l4.eth) + sizeof(no_l4.ip) + 2;
	no_l4.mbuf.pkt_len = no_l4.mbuf.data_len;
	assert_int_equal(gr_mbuf_flow_hash(&no_l4.mbuf, GR_MBUF_FLOW_HASH_RSS), l3_only);

	// a frame cut inside the IP header hashes to zero
	packet_init(&no_l3, RTE_BE16(20000));
	no_l3.mbuf.data_len = sizeof(no_l3.eth) + sizeof(no_l3.ip) - 1;
	no_l3.mbuf.pkt_len = no_l3.mbuf.data_len;
	assert_int_equal(gr_mbuf_flow_hash(&no_l3.mbuf, GR_MBUF_FLOW_HASH_RSS), 0);
	no_l3.mbuf.data_len = sizeof(no_l3.eth) - 1;
	no_l3.mbuf.pkt_len = no_l3.mbuf.data_len;
	assert_int_equal(gr_mbuf_flow_hash(&no_l3.mbuf, GR_MBUF_FLOW_HASH_L2), 0);
}

static void runt_ipv6_hashes_to_zero(void **) {
	struct test_packet6 p;

	packet6_init(&p, RTE_BE16(20000));
	p.mbuf.data_len = sizeof(p.eth) + sizeof(p.ip) - 1;
	p.mbuf.pkt_len = p.mbuf.data_len;
	assert_int_equal(gr_mbuf_flow_hash(&p.mbuf, GR_MBUF_FLOW_HASH_RSS), 0);
}

// L3 is complete but the ports are not: hash the addresses alone, like a next
// header that carries no ports, instead of reading past the packet.
static void truncated_ipv6_ports_hash_like_no_ports(void **) {
	struct test_packet6 no_ports, truncated;

	packet6_init(&no_ports, RTE_BE16(20000));
	no_ports.ip.proto = IPPROTO_HOPOPTS;
	packet6_init(&truncated, RTE_BE16(20000));
	truncated.mbuf.data_len = sizeof(truncated.eth) + sizeof(truncated.ip);
	truncated.mbuf.pkt_len = truncated.mbuf.data_len;

	assert_int_equal(
		gr_mbuf_flow_hash(&no_ports.mbuf, GR_MBUF_FLOW_HASH_RSS),
		gr_mbuf_flow_hash(&truncated.mbuf, GR_MBUF_FLOW_HASH_RSS)
	);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(software_hash_is_stable_per_flow),
		cmocka_unit_test(software_hash_distinguishes_udp_flows),
		cmocka_unit_test(hardware_rss_takes_precedence),
		cmocka_unit_test(tcp_df_hashes_like_no_df),
		cmocka_unit_test(udp_df_hashes_like_no_df),
		cmocka_unit_test(first_fragment_ignores_ports),
		cmocka_unit_test(later_fragment_ignores_ports),
		cmocka_unit_test(fragment_with_df_ignores_ports),
		cmocka_unit_test(ipv4_fragments_share_one_hash),
		cmocka_unit_test(ipv6_fragments_ignore_ports),
		cmocka_unit_test(short_frames_hash_what_they_carry),
		cmocka_unit_test(runt_ipv6_hashes_to_zero),
		cmocka_unit_test(truncated_ipv6_ports_hash_like_no_ports),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
