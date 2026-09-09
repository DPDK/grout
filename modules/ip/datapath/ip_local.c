// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "graph.h"
#include "ip4_datapath.h"
#include "l3.h"
#include "log.h"

#include <rte_mbuf.h>

LOG_TYPE("graph");

enum {
	UNKNOWN_PROTO = 0,
	BAD_LENGTH,
	EDGE_COUNT,
};
static rte_edge_t edges[UINT_NUM_VALUES(uint8_t)] = {UNKNOWN_PROTO};

void ip_input_local_add_proto(uint8_t proto, const char *next_node) {
	LOG(DEBUG, "ip_input_local: proto=%hhu -> %s", proto, next_node);
	if (edges[proto] != UNKNOWN_PROTO)
		ABORT("next node already registered for proto=%hhu", proto);
	edges[proto] = gr_node_attach_parent("ip_input_local", next_node);
}

static uint16_t ip_input_local_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_ipv4_hdr *ip;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);

		if (gr_mbuf_is_traced(mbuf))
			gr_mbuf_trace_add(mbuf, node, 0);

		edge = edges[ip->next_proto_id];
		if (edge != UNKNOWN_PROTO) {
			const struct iface *iface = l3_mbuf_data(mbuf)->iface;
			struct ip_local_mbuf_data *data = ip_local_mbuf_data(mbuf);
			uint16_t hdr_len = rte_ipv4_hdr_len(ip);
			uint16_t total_len = rte_be_to_cpu_16(ip->total_length);

			if (total_len < hdr_len || total_len > rte_pktmbuf_data_len(mbuf)) {
				edge = BAD_LENGTH;
			} else {
				data->src = ip->src_addr;
				data->dst = ip->dst_addr;
				data->len = total_len - hdr_len;
				data->vrf_id = iface->vrf_id;
				data->proto = ip->next_proto_id;
				data->ttl = ip->time_to_live;
				mbuf->packet_type = RTE_PTYPE_L3_IPV4;
				rte_pktmbuf_adj(mbuf, hdr_len);
			}
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

static struct rte_node_register input_node = {
	.name = "ip_input_local",
	.process = ip_input_local_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[UNKNOWN_PROTO] = "ip_input_local_unknown_proto",
		[BAD_LENGTH] = "ip_input_local_bad_length",
	},
};

static struct gr_node_info info = {
	.node = &input_node,
	.type = GR_NODE_T_L3,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip_input_local_unknown_proto);
GR_DROP_REGISTER(ip_input_local_bad_length);

#ifdef __GROUT_UNIT_TEST__
#include "_cmocka.h"

#include <netinet/in.h>

int gr_rte_log_type;
struct log_types log_types = STAILQ_HEAD_INITIALIZER(log_types);
struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);
mock_func(rte_edge_t, gr_node_attach_parent(const char *, const char *));
mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));

// Any edge value that is not UNKNOWN_PROTO, as if a handler was registered.
#define TEST_EDGE 42
#define TEST_PROTO IPPROTO_ICMP
#define TEST_PAYLOAD_LEN 8

struct fake_mbuf {
	struct rte_ipv4_hdr ipv4_hdr;
	uint8_t payload[TEST_PAYLOAD_LEN];
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static struct iface test_iface;

static void fake_mbuf_init(struct fake_mbuf *fm) {
	memset(fm, 0, sizeof(*fm));

	fm->ipv4_hdr.version = 4;
	fm->ipv4_hdr.ihl = sizeof(fm->ipv4_hdr) / 4;
	fm->ipv4_hdr.total_length = rte_cpu_to_be_16(sizeof(fm->ipv4_hdr) + TEST_PAYLOAD_LEN);
	fm->ipv4_hdr.time_to_live = 64;
	fm->ipv4_hdr.next_proto_id = TEST_PROTO;
	fm->ipv4_hdr.src_addr = RTE_IPV4(192, 168, 0, 1);
	fm->ipv4_hdr.dst_addr = RTE_IPV4(192, 168, 0, 2);

	fm->mbuf.buf_addr = &fm->ipv4_hdr;
	fm->mbuf.data_len = sizeof(fm->ipv4_hdr) + TEST_PAYLOAD_LEN;
	fm->mbuf.pkt_len = fm->mbuf.data_len;
	fm->mbuf.nb_segs = 1;

	l3_mbuf_data(&fm->mbuf)->iface = &test_iface;
}

static int setup(void **) {
	edges[TEST_PROTO] = TEST_EDGE;
	return 0;
}

// A total length smaller than the header would make the payload length
// underflow.
static void ip_local_total_length_below_ihl(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	fm.ipv4_hdr.ihl = 10; // 40 bytes of header
	fm.ipv4_hdr.total_length = rte_cpu_to_be_16(sizeof(fm.ipv4_hdr));

	expect_uint_value(rte_node_enqueue_x1, next, BAD_LENGTH);
	ip_input_local_process(NULL, NULL, &obj, 1);
}

// A total length announcing more payload than the packet carries.
static void ip_local_total_length_beyond_mbuf(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	fm.ipv4_hdr.total_length = rte_cpu_to_be_16(fm.mbuf.pkt_len + 1);

	expect_uint_value(rte_node_enqueue_x1, next, BAD_LENGTH);
	ip_input_local_process(NULL, NULL, &obj, 1);
}

// Only the first segment can be read contiguously, which is what every node
// below does, so a payload that reaches into the next one is refused.
static void ip_local_total_length_beyond_first_segment(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	fm.mbuf.data_len = sizeof(fm.ipv4_hdr) + TEST_PAYLOAD_LEN / 2;
	fm.mbuf.pkt_len = sizeof(fm.ipv4_hdr) + TEST_PAYLOAD_LEN;
	fm.mbuf.nb_segs = 2;

	expect_uint_value(rte_node_enqueue_x1, next, BAD_LENGTH);
	ip_input_local_process(NULL, NULL, &obj, 1);
}

// Ethernet padding leaves more bytes than the total length announces, which is
// perfectly valid.
static void ip_local_total_length_below_mbuf(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	fm.mbuf.data_len = fm.mbuf.pkt_len = 60;

	expect_uint_value(rte_node_enqueue_x1, next, TEST_EDGE);
	ip_input_local_process(NULL, NULL, &obj, 1);

	assert_int_equal(ip_local_mbuf_data(&fm.mbuf)->len, TEST_PAYLOAD_LEN);
}

static void ip_local_valid_length(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, TEST_EDGE);
	ip_input_local_process(NULL, NULL, &obj, 1);

	assert_int_equal(ip_local_mbuf_data(&fm.mbuf)->len, TEST_PAYLOAD_LEN);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(ip_local_total_length_below_ihl, setup),
		cmocka_unit_test_setup(ip_local_total_length_beyond_mbuf, setup),
		cmocka_unit_test_setup(ip_local_total_length_beyond_first_segment, setup),
		cmocka_unit_test_setup(ip_local_total_length_below_mbuf, setup),
		cmocka_unit_test_setup(ip_local_valid_length, setup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
