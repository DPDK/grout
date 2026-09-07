// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "graph.h"
#include "iface.h"
#include "ip4.h"
#include "ip4_datapath.h"
#include "mbuf.h"

enum {
	LOOPBACK,
	INVAL,
	NO_IFACE,
	BAD_PROTO,
	EDGE_COUNT,
};

static uint16_t icmp_input_deliver_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct ip_local_mbuf_data *ip;
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

		ip = ip_local_mbuf_data(mbuf);

		if (ip->dst != IPV4_ADDR_BCAST && !ip4_addr_is_mcast(ip->dst)
		    && !addr4_is_local_on_iface(d->iface->id, ip->dst))
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
	.name = "icmp_input_deliver",
	.process = icmp_input_deliver_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[LOOPBACK] = "l4_loopback_output",
		[INVAL] = "icmp_input_deliver_inval",
		[NO_IFACE] = "icmp_input_deliver_no_iface",
		[BAD_PROTO] = "icmp_input_deliver_bad_proto",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L4,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(icmp_input_deliver_inval);
GR_DROP_REGISTER(icmp_input_deliver_no_iface);
GR_DROP_REGISTER(icmp_input_deliver_bad_proto);

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
mock_func(bool, addr4_is_local_on_iface(uint16_t, ip4_addr_t));

struct fake_mbuf {
	struct rte_icmp_hdr icmp;
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static struct iface test_iface, vrf_iface;

static void fake_mbuf_init(struct fake_mbuf *fm) {
	memset(fm, 0, sizeof(*fm));
	fm->mbuf.buf_addr = &fm->icmp;
	fm->mbuf.packet_type = RTE_PTYPE_L3_IPV4;
	mbuf_data(&fm->mbuf)->iface = &test_iface;

	ip_local_mbuf_data(&fm->mbuf)->dst = RTE_IPV4(192, 0, 2, 1);
}

static void ipv4_on_ingress(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	will_return(addr4_is_local_on_iface, true);
	expect_uint_value(rte_node_enqueue_x1, next, LOOPBACK);
	icmp_input_deliver_process(NULL, NULL, &obj, 1);
	assert_ptr_equal(mbuf_data(&fm.mbuf)->iface, &test_iface);
}

static void ipv4_on_vrf(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	will_return(addr4_is_local_on_iface, false);
	will_return(get_vrf_iface, &vrf_iface);
	expect_uint_value(rte_node_enqueue_x1, next, LOOPBACK);
	icmp_input_deliver_process(NULL, NULL, &obj, 1);
	assert_ptr_equal(mbuf_data(&fm.mbuf)->iface, &vrf_iface);
}

static void ipv4_multicast_on_ingress(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	ip_local_mbuf_data(&fm.mbuf)->dst = rte_cpu_to_be_32(RTE_IPV4(224, 0, 0, 1));
	expect_uint_value(rte_node_enqueue_x1, next, LOOPBACK);
	icmp_input_deliver_process(NULL, NULL, &obj, 1);
	assert_ptr_equal(mbuf_data(&fm.mbuf)->iface, &test_iface);
}

static void no_ingress_iface(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	mbuf_data(&fm.mbuf)->iface = NULL;
	expect_uint_value(rte_node_enqueue_x1, next, NO_IFACE);
	icmp_input_deliver_process(NULL, NULL, &obj, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ipv4_on_ingress),
		cmocka_unit_test(ipv4_on_vrf),
		cmocka_unit_test(ipv4_multicast_on_ingress),
		cmocka_unit_test(no_ingress_iface),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
