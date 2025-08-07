// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip6.h>

enum {
	NDP_PROBE = 0,
	INVAL,
	DROP,
	EDGE_COUNT,
};

static uint16_t ndp_na_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	icmp6_opt_found_t lladdr_found;
	struct icmp6_neigh_advert *na;
	struct ip6_local_mbuf_data *d;
	struct rte_ether_addr lladdr;
	const struct nexthop *remote;
	const struct iface *iface;
	struct rte_mbuf *mbuf;
	struct icmp6 *icmp6;
	rte_edge_t edge;

#define ASSERT_NDP(condition)                                                                      \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			edge = INVAL;                                                              \
			goto next;                                                                 \
		}                                                                                  \
	} while (0)

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		d = ip6_local_mbuf_data(mbuf);
		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		iface = d->iface;
		na = PAYLOAD(icmp6);

		// Validation of Neighbor Advertisements
		// https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1.2
		//
		// - The IP Hop Limit field has a value of 255, i.e., the packet
		//   could not possibly have been forwarded by a router.
		ASSERT_NDP(d->hop_limit == 255);
		// - ICMP Checksum is valid. (already checked in icmp6_input)
		//
		// - ICMP Code is 0.
		ASSERT_NDP(icmp6->code == 0);
		// - ICMP length (derived from the IP length) is 24 or more octets.
		ASSERT_NDP(d->len >= 24);
		// - Target Address is not a multicast address.
		ASSERT_NDP(!rte_ipv6_addr_is_mcast(&na->target));
		// - If the IP Destination Address is a multicast address the
		//   Solicited flag is zero.
		ASSERT_NDP(!rte_ipv6_addr_is_mcast(&d->dst) || na->solicited == 0);

		// https://www.rfc-editor.org/rfc/rfc4861.html#section-7.2.5
		//
		// When a valid Neighbor Advertisement is received (either solicited or
		// unsolicited), the Neighbor Cache is searched for the target's entry.
		// If no entry exists, the advertisement SHOULD be silently discarded.
		// There is no need to create an entry if none exists, since the
		// recipient has apparently not initiated any communication with the
		// target.
		remote = nh6_lookup(iface->vrf_id, iface->id, &na->target);
		if (remote == NULL) {
			edge = DROP;
			goto next;
		}

		lladdr_found = icmp6_get_opt(
			mbuf, sizeof(*icmp6) + sizeof(*na), ICMP6_OPT_TARGET_LLADDR, &lladdr
		);
		// If the link layer has addresses and no Target Link-Layer Address
		// option is included, the receiving node SHOULD silently discard the
		// received advertisement.
		ASSERT_NDP(lladdr_found == ICMP6_OPT_FOUND);

		edge = NDP_PROBE;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ndp_na_input",

	.process = ndp_na_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[NDP_PROBE] = "ndp_probe",
		[INVAL] = "ndp_na_input_inval",
		[DROP] = "ndp_na_input_drop",
	},
};

static struct gr_node_info info = {
	.node = &node,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ndp_na_input_inval);
GR_DROP_REGISTER(ndp_na_input_drop);

#ifdef __GROUT_UNIT_TEST__

#include <gr_cmocka.h>

struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);

mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(struct nexthop *, nexthop_lookup(addr_family_t, uint16_t, uint16_t, const void *));
mock_func(void, ndp_probe_input_cb(struct rte_mbuf *));

struct fake_ndp_na_mbuf {
	struct icmp6 icmp6_hdr;
	struct icmp6_neigh_advert na_hdr;
	struct icmp6_opt tlla_opt_hdr;
	struct icmp6_opt_lladdr tlla_opt_payload;
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static struct iface test_iface;

static struct nexthop test_nexthop;

static void init_default_na_mbuf(struct fake_ndp_na_mbuf *ndp_mbuf) {
	memset(ndp_mbuf, 0, sizeof(struct fake_ndp_na_mbuf));

	// Setup ICMP6 packet headers
	ndp_mbuf->icmp6_hdr.type = ICMP6_TYPE_NEIGH_ADVERT;
	ndp_mbuf->icmp6_hdr.code = 0;

	// NA specific packet headers
	ndp_mbuf->na_hdr.router = 0;
	ndp_mbuf->na_hdr.solicited = 1;
	ndp_mbuf->na_hdr.override = 1;
	ndp_mbuf->na_hdr.target = (struct rte_ipv6_addr)
		RTE_IPV6(0xfe80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00aa);

	// TLLA option
	ndp_mbuf->tlla_opt_hdr.type = ICMP6_OPT_TARGET_LLADDR;
	ndp_mbuf->tlla_opt_hdr.len = 1;
	memset(&ndp_mbuf->tlla_opt_payload.mac, 0x22, RTE_ETHER_ADDR_LEN);

	ndp_mbuf->mbuf.buf_addr = &ndp_mbuf->icmp6_hdr;
	ndp_mbuf->mbuf.data_len = sizeof(struct icmp6) + sizeof(struct icmp6_neigh_advert)
		+ sizeof(struct icmp6_opt) + sizeof(struct icmp6_opt_lladdr);
	ndp_mbuf->mbuf.pkt_len = ndp_mbuf->mbuf.data_len;
	ndp_mbuf->mbuf.next = NULL;
	ndp_mbuf->mbuf.ol_flags = 0;
	ndp_mbuf->mbuf.packet_type = RTE_PTYPE_L4_ICMP;

	ip6_local_mbuf_data(&ndp_mbuf->mbuf)->hop_limit = 255;
	ip6_local_mbuf_data(&ndp_mbuf->mbuf)->len = ndp_mbuf->mbuf.data_len;

	ip6_local_mbuf_data(&ndp_mbuf->mbuf)->dst = (struct rte_ipv6_addr)
		RTE_IPV6(0xfe80, 0, 0, 0, 0, 0, 0, 0x00bb);
	ip6_local_mbuf_data(&ndp_mbuf->mbuf)->iface = &test_iface;
}

static void ndp_na_input_hop_limit_invalid(void **) {
	struct fake_ndp_na_mbuf ndp_mbuf_data;
	void *obj = &ndp_mbuf_data.mbuf;
	struct ip6_local_mbuf_data *d = ip6_local_mbuf_data(obj);

	init_default_na_mbuf(&ndp_mbuf_data);

	d->hop_limit = 254;

	expect_value(rte_node_enqueue_x1, next, INVAL);

	ndp_na_input_process(NULL, NULL, &obj, 1);
}

static void ndp_na_input_icmp_code_invalid(void **) {
	struct fake_ndp_na_mbuf ndp_mbuf;
	void *obj = &ndp_mbuf.mbuf;

	init_default_na_mbuf(&ndp_mbuf);

	// Invalid code
	ndp_mbuf.icmp6_hdr.code = 1;

	expect_value(rte_node_enqueue_x1, next, INVAL);

	ndp_na_input_process(NULL, NULL, &obj, 1);
}

static void ndp_na_input_icmp_len_invalid(void **) {
	struct fake_ndp_na_mbuf ndp_mbuf_data;
	void *obj = &ndp_mbuf_data.mbuf;
	struct ip6_local_mbuf_data *d = ip6_local_mbuf_data(obj);

	init_default_na_mbuf(&ndp_mbuf_data);

	//Invalid length
	d->len = 23;

	expect_value(rte_node_enqueue_x1, next, INVAL);

	ndp_na_input_process(NULL, NULL, &obj, 1);
}

static void ndp_na_input_target_mcast(void **) {
	struct fake_ndp_na_mbuf ndp_mbuf;
	void *obj = &ndp_mbuf.mbuf;

	init_default_na_mbuf(&ndp_mbuf);

	// Set target to a multicast address FF02::1
	ndp_mbuf.na_hdr.target = (struct rte_ipv6_addr)
		RTE_IPV6(0xff02, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1);

	expect_value(rte_node_enqueue_x1, next, INVAL);

	ndp_na_input_process(NULL, NULL, &obj, 1);
}

static void ndp_na_input_dst_mcast_solicited_is_set(void **) {
	struct fake_ndp_na_mbuf ndp_mbuf_data;
	void *obj = &ndp_mbuf_data.mbuf;
	struct ip6_local_mbuf_data *d = ip6_local_mbuf_data(&ndp_mbuf_data.mbuf);

	init_default_na_mbuf(&ndp_mbuf_data);

	// dst is mcast and na_hdr.solicited is 1. Fails: !mcast(dst) || solicited==0
	d->dst = (struct rte_ipv6_addr)RTE_IPV6(0xff02, 0, 0, 0, 0, 0, 0, 1);

	expect_value(rte_node_enqueue_x1, next, INVAL);

	ndp_na_input_process(NULL, NULL, (void **)&obj, 1);
}

static void ndp_na_input_tlla_opt_type_invalid(void **) {
	struct fake_ndp_na_mbuf ndp_mbuf;
	void *obj = &ndp_mbuf.mbuf;

	init_default_na_mbuf(&ndp_mbuf);

	// Invalid option type
	ndp_mbuf.tlla_opt_hdr.type = ICMP6_OPT_MTU;

	will_return(nexthop_lookup, &test_nexthop);

	expect_value(rte_node_enqueue_x1, next, INVAL);

	ndp_na_input_process(NULL, NULL, &obj, 1);
}

static void ndp_na_input_tlla_opt_len_invalid(void **) {
	struct fake_ndp_na_mbuf ndp_mbuf;
	void *obj = &ndp_mbuf.mbuf;

	init_default_na_mbuf(&ndp_mbuf);

	// Invalid option length
	ndp_mbuf.tlla_opt_hdr.len = 0;

	will_return(nexthop_lookup, &test_nexthop);

	expect_value(rte_node_enqueue_x1, next, INVAL);

	ndp_na_input_process(NULL, NULL, &obj, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ndp_na_input_hop_limit_invalid),
		cmocka_unit_test(ndp_na_input_icmp_len_invalid),
		cmocka_unit_test(ndp_na_input_icmp_code_invalid),
		cmocka_unit_test(ndp_na_input_target_mcast),
		cmocka_unit_test(ndp_na_input_dst_mcast_solicited_is_set),
		cmocka_unit_test(ndp_na_input_tlla_opt_type_invalid),
		cmocka_unit_test(ndp_na_input_tlla_opt_len_invalid),

	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif
