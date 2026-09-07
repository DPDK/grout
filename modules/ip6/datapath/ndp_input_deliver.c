// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025-2026 Robin Jarry
// Copyright (c) 2026 Christopher Dziomba

#include "graph.h"
#include "icmp6.h"
#include "iface.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "mbuf.h"

enum {
	LOOPBACK,
	INVAL,
	NO_IFACE,
	EDGE_COUNT,
};

static bool ndp_ra_valid(const struct ip6_local_mbuf_data *d, const struct icmp6 *icmp6) {
	// Validation of Router Advertisements (RFC 4861 section 6.1.2).
	// The ICMP checksum has already been checked in icmp6_input.
	return d->hop_limit == 255 && icmp6->code == 0
		&& d->len >= sizeof(*icmp6) + sizeof(struct icmp6_router_advert)
		&& rte_ipv6_addr_is_linklocal(&d->src);
}

static uint16_t ndp_input_deliver_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *mbuf;
	struct mbuf_data *d;
	rte_edge_t next;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		d = mbuf_data(mbuf);
		next = LOOPBACK;
		if (d->iface == NULL) {
			next = NO_IFACE;
			goto next;
		}

		const struct ip6_local_mbuf_data *ip = ip6_local_mbuf_data(mbuf);

		if (ip->proto == IPPROTO_ICMPV6
		    && rte_pktmbuf_mtod(mbuf, struct icmp6 *)->type == ICMP6_TYPE_ROUTER_ADVERT) {
			const struct icmp6 *icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);

			if (!ndp_ra_valid(ip, icmp6)) {
				next = INVAL;
				goto next;
			}
		}
		// Multicast packets stay on the incoming TAP, including RAs.
		if (!rte_ipv6_addr_is_mcast(&ip->dst)
		    && !addr6_is_local_on_iface(d->iface->id, &ip->dst))
			d->iface = get_vrf_iface(d->iface->vrf_id);
		if (d->iface == NULL)
			next = NO_IFACE;
next:
		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register node = {
	.name = "ndp_input_deliver",
	.process = ndp_input_deliver_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[LOOPBACK] = "l4_loopback_output",
		[INVAL] = "ndp_input_deliver_inval",
		[NO_IFACE] = "ndp_input_deliver_no_iface",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L4,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ndp_input_deliver_inval);
GR_DROP_REGISTER(ndp_input_deliver_no_iface);

#ifdef __GROUT_UNIT_TEST__
#include "_cmocka.h"
#include "log.h"

int gr_rte_log_type;
struct log_types log_types = STAILQ_HEAD_INITIALIZER(log_types);
struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);
mock_func(rte_edge_t, gr_node_attach_parent(const char *, const char *));
mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(struct iface *, get_vrf_iface(uint16_t));
mock_func(bool, addr6_is_local_on_iface(uint16_t, const struct rte_ipv6_addr *));

struct fake_mbuf {
	struct icmp6 icmp6;
	uint8_t payload[sizeof(struct icmp6_router_advert)];
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static struct iface test_iface, vrf_iface;

static void fake_mbuf_init(struct fake_mbuf *fm) {
	memset(fm, 0, sizeof(*fm));
	fm->mbuf.buf_addr = &fm->icmp6;
	fm->mbuf.packet_type = RTE_PTYPE_L3_IPV6;
	mbuf_data(&fm->mbuf)->iface = &test_iface;

	ip6_local_mbuf_data(&fm->mbuf)->proto = IPPROTO_ICMPV6;
	fm->icmp6.type = ICMP6_TYPE_ECHO_REPLY;
}

static void ipv6_on_vrf(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	will_return(addr6_is_local_on_iface, false);
	will_return(get_vrf_iface, &vrf_iface);
	expect_uint_value(rte_node_enqueue_x1, next, LOOPBACK);
	ndp_input_deliver_process(NULL, NULL, &obj, 1);
	assert_ptr_equal(mbuf_data(&fm.mbuf)->iface, &vrf_iface);
}

static void ipv6_on_ingress(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	will_return(addr6_is_local_on_iface, true);
	expect_uint_value(rte_node_enqueue_x1, next, LOOPBACK);
	ndp_input_deliver_process(NULL, NULL, &obj, 1);
	assert_ptr_equal(mbuf_data(&fm.mbuf)->iface, &test_iface);
}

static void ipv6_no_vrf(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	will_return(addr6_is_local_on_iface, false);
	will_return(get_vrf_iface, NULL);
	expect_uint_value(rte_node_enqueue_x1, next, NO_IFACE);
	ndp_input_deliver_process(NULL, NULL, &obj, 1);
}

static void udp_does_not_validate_ra(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	ip6_local_mbuf_data(&fm.mbuf)->proto = IPPROTO_UDP;
	fm.icmp6.type = ICMP6_TYPE_ROUTER_ADVERT;
	will_return(addr6_is_local_on_iface, true);
	expect_uint_value(rte_node_enqueue_x1, next, LOOPBACK);
	ndp_input_deliver_process(NULL, NULL, &obj, 1);
}

static void fake_ra_init(struct fake_mbuf *fm) {
	struct ip6_local_mbuf_data *d;

	fake_mbuf_init(fm);
	fm->icmp6.type = ICMP6_TYPE_ROUTER_ADVERT;
	d = ip6_local_mbuf_data(&fm->mbuf);
	d->hop_limit = 255;
	d->len = sizeof(fm->icmp6) + sizeof(fm->payload);
	d->src.a[0] = 0xfe;
	d->src.a[1] = 0x80;
	d->dst.a[0] = 0xff;
	d->dst.a[1] = 0x02;
}

static void ra_on_ingress(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_ra_init(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, LOOPBACK);
	ndp_input_deliver_process(NULL, NULL, &obj, 1);
	assert_ptr_equal(mbuf_data(&fm.mbuf)->iface, &test_iface);
}

static void ra_unicast_on_vrf(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_ra_init(&fm);
	ip6_local_mbuf_data(&fm.mbuf)->dst.a[0] = 0xfe;
	ip6_local_mbuf_data(&fm.mbuf)->dst.a[1] = 0x80;
	will_return(addr6_is_local_on_iface, false);
	will_return(get_vrf_iface, &vrf_iface);
	expect_uint_value(rte_node_enqueue_x1, next, LOOPBACK);
	ndp_input_deliver_process(NULL, NULL, &obj, 1);
	assert_ptr_equal(mbuf_data(&fm.mbuf)->iface, &vrf_iface);
}

static void ra_bad_hop_limit(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_ra_init(&fm);
	ip6_local_mbuf_data(&fm.mbuf)->hop_limit = 64;
	expect_uint_value(rte_node_enqueue_x1, next, INVAL);
	ndp_input_deliver_process(NULL, NULL, &obj, 1);
}

static void ra_bad_code(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_ra_init(&fm);
	fm.icmp6.code = 1;
	expect_uint_value(rte_node_enqueue_x1, next, INVAL);
	ndp_input_deliver_process(NULL, NULL, &obj, 1);
}

static void ra_too_short(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_ra_init(&fm);
	ip6_local_mbuf_data(&fm.mbuf)->len--;
	expect_uint_value(rte_node_enqueue_x1, next, INVAL);
	ndp_input_deliver_process(NULL, NULL, &obj, 1);
}

static void ra_non_linklocal_source(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_ra_init(&fm);
	ip6_local_mbuf_data(&fm.mbuf)->src.a[0] = 0x20;
	expect_uint_value(rte_node_enqueue_x1, next, INVAL);
	ndp_input_deliver_process(NULL, NULL, &obj, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ipv6_on_ingress),
		cmocka_unit_test(ipv6_on_vrf),
		cmocka_unit_test(ipv6_no_vrf),
		cmocka_unit_test(udp_does_not_validate_ra),
		cmocka_unit_test(ra_on_ingress),
		cmocka_unit_test(ra_unicast_on_vrf),
		cmocka_unit_test(ra_bad_hop_limit),
		cmocka_unit_test(ra_bad_code),
		cmocka_unit_test(ra_too_short),
		cmocka_unit_test(ra_non_linklocal_source),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
