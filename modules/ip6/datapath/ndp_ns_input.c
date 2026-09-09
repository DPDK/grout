// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "control_output.h"
#include "graph.h"
#include "icmp6.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "mbuf.h"
#include "trace.h"

#include <rte_ether.h>
#include <rte_ip6.h>

enum {
	CONTROL = 0,
	INVAL,
	DROP,
	EDGE_COUNT,
};

static uint16_t ndp_ns_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct nexthop_info_l3 *l3;
	icmp6_opt_found_t lladdr_found;
	struct icmp6_neigh_solicit *ns;
	struct ip6_local_mbuf_data d;
	struct rte_ether_addr lladdr;
	const struct nexthop *local;
	struct rte_mbuf *mbuf;
	struct icmp6 *icmp6;
	rte_edge_t next;

#define ASSERT_NDP(condition)                                                                      \
	do {                                                                                       \
		if (!(condition)) {                                                                \
			next = INVAL;                                                              \
			goto next;                                                                 \
		}                                                                                  \
	} while (0)

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];

		d = *ip6_local_mbuf_data(mbuf);
		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		ns = PAYLOAD(icmp6);

		// Validation of Neighbor Solicitations
		// https://www.rfc-editor.org/rfc/rfc4861.html#section-7.1.1
		//
		// - The IP Hop Limit field has a value of 255, i.e., the packet
		//   could not possibly have been forwarded by a router.
		ASSERT_NDP(d.hop_limit == 255);
		// - ICMP Checksum is valid. (already checked in icmp6_input)
		//
		// - ICMP Code is 0.
		ASSERT_NDP(icmp6->code == 0);
		// - ICMP length (derived from the IP length) is 24 or more octets.
		ASSERT_NDP(d.len >= sizeof(*icmp6) + sizeof(*ns));
		// - Target Address is not a multicast address.
		ASSERT_NDP(!rte_ipv6_addr_is_mcast(&ns->target));

		local = nh6_lookup(d.iface->vrf_id, d.iface->id, &ns->target);
		if (local == NULL) {
			next = DROP;
			goto next;
		}
		l3 = nexthop_info_l3(local);
		if (!(l3->flags & GR_NH_F_LOCAL)) {
			next = DROP;
			goto next;
		}

		if (rte_ipv6_addr_is_unspec(&d.src)) {
			// - If the IP source address is the unspecified address, the IP
			//   destination address is a solicited-node multicast address.
			ASSERT_NDP(rte_ipv6_addr_is_mcast(&d.dst));
			// - If the IP source address is the unspecified address, there is
			//   no source link-layer address option in the message.
			lladdr_found = icmp6_get_opt(
				mbuf, sizeof(*icmp6) + sizeof(*ns), ICMP6_OPT_SRC_LLADDR, &lladdr
			);
			ASSERT_NDP(lladdr_found == ICMP6_OPT_NOT_FOUND);
		}

		control_output_set_cb(mbuf, ndp_probe_input_cb, 0);
		next = CONTROL;
next:
		if (gr_mbuf_is_traced(mbuf)) {
			uint8_t trace_len = RTE_MIN(d.len, GR_TRACE_ITEM_MAX_LEN);
			struct icmp6 *t = gr_mbuf_trace_add(mbuf, node, trace_len);
			memcpy(t, icmp6, trace_len);
		}
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ndp_ns_input",

	.process = ndp_ns_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[CONTROL] = "control_output",
		[INVAL] = "ndp_ns_input_inval",
		[DROP] = "ndp_ns_input_drop",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L4,
	.trace_format = (gr_trace_format_cb_t)trace_icmp6_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ndp_ns_input_inval);
GR_DROP_REGISTER(ndp_ns_input_drop);

#ifdef __GROUT_UNIT_TEST__

#include "_cmocka.h"

struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);

int cq_callback_offset;
int cq_priv_offset;
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(int, trace_icmp6_format(char *, size_t, const struct icmp6 *, size_t));
mock_func(struct nexthop *, nexthop_lookup_l3(addr_family_t, uint16_t, uint16_t, const void *));
mock_func(void, ndp_probe_input_cb(void *, uintptr_t, const struct control_queue_drain *));

struct fake_ndp_ns_mbuf {
	struct icmp6 icmp6_hdr;
	struct icmp6_neigh_solicit ns_hdr;
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static struct iface test_iface;

static void init_default_ns_mbuf(struct fake_ndp_ns_mbuf *ndp_mbuf) {
	memset(ndp_mbuf, 0, sizeof(*ndp_mbuf));

	ndp_mbuf->icmp6_hdr.type = ICMP6_TYPE_NEIGH_SOLICIT;
	ndp_mbuf->icmp6_hdr.code = 0;
	ndp_mbuf->ns_hdr.target = (struct rte_ipv6_addr)RTE_IPV6(
		0xfe80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00aa
	);

	ndp_mbuf->mbuf.buf_addr = &ndp_mbuf->icmp6_hdr;
	ndp_mbuf->mbuf.data_len = sizeof(struct icmp6) + sizeof(struct icmp6_neigh_solicit);
	ndp_mbuf->mbuf.pkt_len = ndp_mbuf->mbuf.data_len;
	ndp_mbuf->mbuf.next = NULL;
	ndp_mbuf->mbuf.ol_flags = 0;
	ndp_mbuf->mbuf.packet_type = RTE_PTYPE_L4_ICMP;

	ip6_local_mbuf_data(&ndp_mbuf->mbuf)->hop_limit = 255;
	ip6_local_mbuf_data(&ndp_mbuf->mbuf)->len = ndp_mbuf->mbuf.data_len;
	ip6_local_mbuf_data(&ndp_mbuf->mbuf)->src = (struct rte_ipv6_addr)RTE_IPV6(
		0xfe80, 0, 0, 0, 0, 0, 0, 0x00bb
	);
	ip6_local_mbuf_data(&ndp_mbuf->mbuf)->dst = (struct rte_ipv6_addr)RTE_IPV6(
		0xfe80, 0, 0, 0, 0, 0, 0, 0x00aa
	);
	ip6_local_mbuf_data(&ndp_mbuf->mbuf)->iface = &test_iface;
}

// A solicitation carrying only the generic ICMPv6 header has no target address
// to read. RFC 4861 requires 24 octets.
static void ndp_ns_input_icmp_len_invalid(void **) {
	struct fake_ndp_ns_mbuf ndp_mbuf;
	void *obj = &ndp_mbuf.mbuf;

	init_default_ns_mbuf(&ndp_mbuf);
	ip6_local_mbuf_data(obj)->len = GR_ICMP6_HDR_LEN;

	expect_uint_value(rte_node_enqueue_x1, next, INVAL);

	ndp_ns_input_process(NULL, NULL, &obj, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ndp_ns_input_icmp_len_invalid),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif
