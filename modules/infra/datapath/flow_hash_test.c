// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Harrison Caldicott

#include "_cmocka.h"
#include "flow_hash.h"

#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_udp.h>

#include <stddef.h>
#include <string.h>

struct test_packet {
	struct rte_mbuf mbuf;
	struct rte_ether_hdr eth;
	struct rte_ipv4_hdr ip;
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

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(software_hash_is_stable_per_flow),
		cmocka_unit_test(software_hash_distinguishes_udp_flows),
		cmocka_unit_test(hardware_rss_takes_precedence),
		cmocka_unit_test(ipv4_fragments_share_one_hash),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
