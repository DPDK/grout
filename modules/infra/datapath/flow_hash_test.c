// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Harrison Caldicott

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

static void cached_hash_prefers_hardware_rss(void **) {
	struct test_packet p;

	packet_init(&p, RTE_BE16(20000));
	p.mbuf.ol_flags = RTE_MBUF_F_RX_RSS_HASH;
	p.mbuf.hash.rss = 0x12345678;

	assert_int_equal(gr_mbuf_flow_hash_get(&p.mbuf), 0x12345678);
	assert_true(gr_mbuf_flow_hash_is_valid(&p.mbuf));
	assert_int_equal(p.mbuf.hash.rss, 0x12345678);
}

static void software_hash_is_computed_once(void **) {
	struct test_packet p;
	uint32_t expected;

	packet_init(&p, RTE_BE16(20000));
	expected = gr_mbuf_flow_hash(&p.mbuf, GR_MBUF_FLOW_HASH_L3_L4);

	assert_false(gr_mbuf_flow_hash_is_valid(&p.mbuf));
	assert_int_equal(gr_mbuf_flow_hash_get(&p.mbuf), expected);
	assert_true(gr_mbuf_flow_hash_is_valid(&p.mbuf));
	assert_int_equal(p.mbuf.hash.rss, expected);

	// the cached value is reused, not recomputed
	p.udp.src_port = RTE_BE16(20001);
	assert_int_equal(gr_mbuf_flow_hash_get(&p.mbuf), expected);
}

static void cached_software_hash_distinguishes_udp_flows(void **) {
	struct test_packet a, b;

	packet_init(&a, RTE_BE16(20000));
	packet_init(&b, RTE_BE16(20001));
	assert_int_not_equal(gr_mbuf_flow_hash_get(&a.mbuf), gr_mbuf_flow_hash_get(&b.mbuf));
}

static void l3_ipv4_hash_matches_ethernet_hash(void **) {
	struct test_packet p;
	uint32_t expected;

	packet_init(&p, RTE_BE16(20000));
	expected = gr_mbuf_flow_hash(&p.mbuf, GR_MBUF_FLOW_HASH_L3_L4);
	assert_non_null(rte_pktmbuf_adj(&p.mbuf, sizeof(p.eth)));

	assert_int_equal(
		gr_mbuf_flow_hash_get_l3(&p.mbuf, RTE_BE16(RTE_ETHER_TYPE_IPV4)), expected
	);
	assert_true(gr_mbuf_flow_hash_is_valid(&p.mbuf));
}

static void l3_ipv6_hash_matches_ethernet_hash(void **) {
	struct test_packet6 p;
	uint32_t expected;

	packet6_init(&p, RTE_BE16(20000));
	expected = gr_mbuf_flow_hash(&p.mbuf, GR_MBUF_FLOW_HASH_L3_L4);
	assert_non_null(rte_pktmbuf_adj(&p.mbuf, sizeof(p.eth)));

	assert_int_equal(
		gr_mbuf_flow_hash_get_l3(&p.mbuf, RTE_BE16(RTE_ETHER_TYPE_IPV6)), expected
	);
	assert_true(gr_mbuf_flow_hash_is_valid(&p.mbuf));
}

static void l3_hash_imports_hardware_rss(void **) {
	struct test_packet p;

	packet_init(&p, RTE_BE16(20000));
	assert_non_null(rte_pktmbuf_adj(&p.mbuf, sizeof(p.eth)));
	p.mbuf.ol_flags = RTE_MBUF_F_RX_RSS_HASH;
	p.mbuf.hash.rss = 0x12345678;

	assert_int_equal(
		gr_mbuf_flow_hash_get_l3(&p.mbuf, RTE_BE16(RTE_ETHER_TYPE_IPV4)), 0x12345678
	);
	assert_true(gr_mbuf_flow_hash_is_valid(&p.mbuf));
}

static void cached_ipv4_fragments_share_one_hash(void **) {
	struct test_packet first, later;

	packet_init(&first, RTE_BE16(20000));
	packet_init(&later, RTE_BE16(20001));
	first.ip.fragment_offset = RTE_BE16(RTE_IPV4_HDR_MF_FLAG);
	later.ip.fragment_offset = RTE_BE16(1);

	assert_int_equal(gr_mbuf_flow_hash_get(&first.mbuf), gr_mbuf_flow_hash_get(&later.mbuf));
}

static void validity_is_cleared_on_reset(void **) {
	struct test_packet p;

	packet_init(&p, RTE_BE16(20000));
	gr_mbuf_flow_hash_set(&p.mbuf, 0x12345678);
	assert_true(gr_mbuf_flow_hash_is_valid(&p.mbuf));

	rte_pktmbuf_reset(&p.mbuf);
	assert_false(gr_mbuf_flow_hash_is_valid(&p.mbuf));
}

static void invalidate_forces_recompute_on_inner_frame(void **) {
	struct test_packet p;
	uint32_t expected;

	packet_init(&p, RTE_BE16(20000));
	expected = gr_mbuf_flow_hash(&p.mbuf, GR_MBUF_FLOW_HASH_L3_L4);
	// pretend the NIC hashed a (since removed) outer tunnel header
	gr_mbuf_flow_hash_set(&p.mbuf, ~expected);

	gr_mbuf_flow_hash_invalidate(&p.mbuf);
	assert_false(gr_mbuf_flow_hash_is_valid(&p.mbuf));
	assert_int_equal(gr_mbuf_flow_hash_get(&p.mbuf), expected);
	assert_true(gr_mbuf_flow_hash_is_valid(&p.mbuf));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(software_hash_is_stable_per_flow),
		cmocka_unit_test(software_hash_distinguishes_udp_flows),
		cmocka_unit_test(hardware_rss_takes_precedence),
		cmocka_unit_test(ipv4_fragments_share_one_hash),
		cmocka_unit_test(cached_hash_prefers_hardware_rss),
		cmocka_unit_test(software_hash_is_computed_once),
		cmocka_unit_test(cached_software_hash_distinguishes_udp_flows),
		cmocka_unit_test(l3_ipv4_hash_matches_ethernet_hash),
		cmocka_unit_test(l3_ipv6_hash_matches_ethernet_hash),
		cmocka_unit_test(l3_hash_imports_hardware_rss),
		cmocka_unit_test(cached_ipv4_fragments_share_one_hash),
		cmocka_unit_test(validity_is_cleared_on_reset),
		cmocka_unit_test(invalidate_forces_recompute_on_inner_frame),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
