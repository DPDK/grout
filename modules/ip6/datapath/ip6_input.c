// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_eth.h>
#include <gr_fib6.h>
#include <gr_graph.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_fib6.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

enum edges {
	FORWARD = 0,
	OUTPUT,
	LOCAL,
	DEST_UNREACH,
	NOT_MEMBER,
	OTHER_HOST,
	BAD_VERSION,
	BAD_ADDR,
	BAD_LENGTH,
	EDGE_COUNT,
};

static rte_edge_t nh_type_edges[256] = {FORWARD};

void ip6_input_register_nexthop_type(gr_nh_type_t type, const char *next_node) {
	LOG(DEBUG, "ip6_input: nexthop type=%u -> %s", type, next_node);
	if (type == 0)
		ABORT("invalid nexthop type=%u", type);
	if (nh_type_edges[type] != FORWARD)
		ABORT("next node already registered for nexthop type=%u", type);
	nh_type_edges[type] = gr_node_attach_parent("ip6_input", next_node);
}

static uint16_t
ip6_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct nexthop_info_l3 *l3;
	struct ip6_output_mbuf_data *d;
	struct eth_input_mbuf_data *e;
	const struct iface *iface;
	const struct nexthop *nh;
	struct rte_ipv6_hdr *ip;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv6_hdr *);
		e = eth_input_mbuf_data(mbuf);
		iface = e->iface;
		nh = NULL;

		if (rte_pktmbuf_data_len(mbuf) < sizeof(struct rte_ipv6_hdr)) {
			// XXX: call rte_pktmuf_data_len is used to ensure that the IPv6 header
			// is located on the first segment. IPv6 headers located on the second,
			// third or subsequent segments, as well spanning segment boundaries, are
			// not currently handled.
			edge = BAD_LENGTH;
			goto next;
		}

		if (rte_ipv6_check_version(ip)) {
			edge = BAD_VERSION;
			goto next;
		}

		if (rte_ipv6_addr_is_mcast(&ip->src_addr)
		    || rte_ipv6_addr_is_unspec(&ip->dst_addr)) {
			edge = BAD_ADDR;
			goto next;
		}

		if (unlikely(rte_ipv6_addr_is_mcast(&ip->dst_addr))) {
			switch (rte_ipv6_mc_scope(&ip->dst_addr)) {
			case RTE_IPV6_MC_SCOPE_NONE:
				// RFC4291 2.7:
				// Nodes must not originate a packet to a multicast address
				// whose scope field contains the reserved value 0; if such
				// a packet is received, it must be silently dropped.
			case RTE_IPV6_MC_SCOPE_IFACELOCAL:
				// This should only happen if the input interface is a loopback
				// interface. For now, we do not have support for these.
				edge = BAD_ADDR;
				break;
			default:
				nh = mcast6_get_member(iface->id, &ip->dst_addr);
				if (nh == NULL)
					edge = NOT_MEMBER;
				else
					edge = LOCAL;
			}
			goto next;
		}

		switch (e->domain) {
		case ETH_DOMAIN_LOOPBACK:
		case ETH_DOMAIN_LOCAL:
			// Packet sent to our ethernet address.
			break;
		case ETH_DOMAIN_BROADCAST:
		case ETH_DOMAIN_MULTICAST:
			// Non unicast ethernet destination. No need for a route lookup.
			edge = LOCAL;
			goto next;
		case ETH_DOMAIN_OTHER:
		case ETH_DOMAIN_UNKNOWN:
			// Drop all packets not sent to our ethernet address
			edge = OTHER_HOST;
			goto next;
		}

		nh = fib6_lookup(iface->vrf_id, iface->id, &ip->dst_addr);
		if (nh == NULL) {
			edge = DEST_UNREACH;
			goto next;
		}

		edge = nh_type_edges[nh->type];
		if (edge != FORWARD)
			goto next;

		if (e->domain == ETH_DOMAIN_LOOPBACK) {
			edge = OUTPUT;
		} else if (nh->type == GR_NH_T_L3) {
			// If the resolved next hop is local and the destination IP is ourselves,
			// send to ip6_local.
			l3 = nexthop_info_l3(nh);
			if (l3->flags & GR_NH_F_LOCAL && rte_ipv6_addr_eq(&ip->dst_addr, &l3->ipv6))
				edge = LOCAL;
		}
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_ipv6_hdr *t = gr_mbuf_trace_add(mbuf, node, sizeof(*t));
			*t = *ip;
		}
		// Store the resolved next hop for ip6_output to avoid a second route lookup.
		d = ip6_output_mbuf_data(mbuf);
		d->nh = nh;
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static void ip6_input_register(void) {
	gr_eth_input_add_type(RTE_BE16(RTE_ETHER_TYPE_IPV6), "ip6_input");
	loopback_input_add_type(RTE_BE16(RTE_ETHER_TYPE_IPV6), "ip6_input");
	ip6_input_register_nexthop_type(GR_NH_T_BLACKHOLE, "ip6_blackhole");
	ip6_input_register_nexthop_type(GR_NH_T_REJECT, "ip6_error_dest_unreach");
}

static struct rte_node_register input_node = {
	.name = "ip6_input",

	.process = ip6_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[FORWARD] = "ip6_forward",
		[OUTPUT] = "ip6_output",
		[LOCAL] = "ip6_input_local",
		[DEST_UNREACH] = "ip6_error_dest_unreach",
		[NOT_MEMBER] = "ip6_input_not_member",
		[OTHER_HOST] = "ip6_input_other_host",
		[BAD_VERSION] = "ip6_input_bad_version",
		[BAD_ADDR] = "ip6_input_bad_addr",
		[BAD_LENGTH] = "ip6_input_bad_length",
	},
};

static struct gr_node_info info = {
	.node = &input_node,
	.register_callback = ip6_input_register,
	.trace_format = (gr_trace_format_cb_t)trace_ip6_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip6_input_not_member);
GR_DROP_REGISTER(ip6_input_other_host);
GR_DROP_REGISTER(ip6_input_bad_version);
GR_DROP_REGISTER(ip6_input_bad_addr);
GR_DROP_REGISTER(ip6_input_bad_length);
GR_DROP_REGISTER(ip6_blackhole);

#ifdef __GROUT_UNIT_TEST__
#include <gr_cmocka.h>

int gr_rte_log_type;
struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);

mock_func(rte_edge_t, gr_node_attach_parent(const char *, const char *));
mock_func(const struct nexthop *, fib6_lookup(uint16_t, uint16_t, const struct rte_ipv6_addr *));
mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(int, trace_ip6_format(char *, size_t, const struct rte_ipv6_hdr *, size_t));
mock_func(void, gr_eth_input_add_type(rte_be16_t, const char *));
mock_func(void, loopback_input_add_type(rte_be16_t, const char *));
mock_func(struct nexthop *, mcast6_get_member(uint16_t, const struct rte_ipv6_addr *));

struct fake_mbuf {
	struct rte_ipv6_hdr ipv6_hdr;
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static void ipv6_init_default_mbuf(struct fake_mbuf *fake_mbuf) {
	memset(fake_mbuf, 0, sizeof(struct fake_mbuf));

	fake_mbuf->ipv6_hdr.vtc_flow = rte_cpu_to_be_32(6 << 28);
	fake_mbuf->ipv6_hdr.payload_len = rte_cpu_to_be_16(0);
	fake_mbuf->ipv6_hdr.proto = IPPROTO_NONE;
	fake_mbuf->ipv6_hdr.hop_limits = 64;
	fake_mbuf->ipv6_hdr.src_addr = (struct rte_ipv6_addr)RTE_IPV6(0, 3, 0, 3, 1, 9, 8, 8);
	fake_mbuf->ipv6_hdr.dst_addr = (struct rte_ipv6_addr)RTE_IPV6(0, 3, 0, 5, 2, 0, 2, 4);

	fake_mbuf->mbuf.buf_addr = &fake_mbuf->ipv6_hdr;
	fake_mbuf->mbuf.data_len = sizeof(struct rte_ipv6_hdr);
	fake_mbuf->mbuf.pkt_len = sizeof(struct rte_ipv6_hdr);
	fake_mbuf->mbuf.next = NULL;
	fake_mbuf->mbuf.ol_flags = 0;
	fake_mbuf->mbuf.packet_type = RTE_PTYPE_L3_IPV6;

	eth_input_mbuf_data(&fake_mbuf->mbuf)->domain = ETH_DOMAIN_OTHER;
}

static void ip6_input_invalid_version(void **) {
	struct fake_mbuf fake_mbuf;
	void *obj = &fake_mbuf.mbuf;

	ipv6_init_default_mbuf(&fake_mbuf);

	fake_mbuf.ipv6_hdr.vtc_flow = rte_cpu_to_be_32(5 << 28);
	expect_value(rte_node_enqueue_x1, next, BAD_VERSION);
	ip6_input_process(NULL, NULL, &obj, 1);
}

static void ip6_input_invalid_src_mcast_addr(void **) {
	struct fake_mbuf fake_mbuf;
	void *obj = &fake_mbuf.mbuf;

	ipv6_init_default_mbuf(&fake_mbuf);

	// clang-format off
	fake_mbuf.ipv6_hdr.src_addr = (struct rte_ipv6_addr)
		RTE_IPV6(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff);
	// clang-format on
	expect_value(rte_node_enqueue_x1, next, BAD_ADDR);
	ip6_input_process(NULL, NULL, &obj, 1);
}

static void ip6_input_invalid_dst_unspec_addr(void **) {
	struct fake_mbuf fake_mbuf;
	void *obj = &fake_mbuf.mbuf;

	ipv6_init_default_mbuf(&fake_mbuf);

	// clang-format off
	fake_mbuf.ipv6_hdr.dst_addr = (struct rte_ipv6_addr)
		RTE_IPV6(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0);
	// clang-format on
	expect_value(rte_node_enqueue_x1, next, BAD_ADDR);
	ip6_input_process(NULL, NULL, &obj, 1);
}

static void ip6_input_invalid_dst_mcast_addr(void **) {
	struct fake_mbuf fake_mbuf;
	void *obj = &fake_mbuf.mbuf;

	ipv6_init_default_mbuf(&fake_mbuf);

	// Multicast scope none
	// clang-format off
	fake_mbuf.ipv6_hdr.dst_addr = (struct rte_ipv6_addr)
		RTE_IPV6(0xff00, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1);
	// clang-format on
	expect_value(rte_node_enqueue_x1, next, BAD_ADDR);
	ip6_input_process(NULL, NULL, &obj, 1);

	// Multicast iface local
	// clang-format off
	fake_mbuf.ipv6_hdr.dst_addr = (struct rte_ipv6_addr)
		RTE_IPV6(0xff00, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1);
	// clang-format on
	expect_value(rte_node_enqueue_x1, next, BAD_ADDR);
	ip6_input_process(NULL, NULL, &obj, 1);
}

static void ip6_input_invalid_mbuf_len(void **) {
	struct fake_mbuf fake_mbuf;
	void *obj = &fake_mbuf.mbuf;

	ipv6_init_default_mbuf(&fake_mbuf);

	fake_mbuf.mbuf.data_len = sizeof(struct rte_ipv6_hdr) / 2;
	expect_value(rte_node_enqueue_x1, next, BAD_LENGTH);
	ip6_input_process(NULL, NULL, &obj, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ip6_input_invalid_version),
		cmocka_unit_test(ip6_input_invalid_src_mcast_addr),
		cmocka_unit_test(ip6_input_invalid_dst_unspec_addr),
		cmocka_unit_test(ip6_input_invalid_dst_mcast_addr),
		cmocka_unit_test(ip6_input_invalid_mbuf_len),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
