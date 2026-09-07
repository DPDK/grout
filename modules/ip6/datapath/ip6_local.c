// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "graph.h"
#include "ip6_datapath.h"
#include "l3.h"
#include "log.h"

#include <rte_ip6.h>
#include <rte_mbuf.h>

LOG_TYPE("graph");

enum {
	UNKNOWN_PROTO = 0,
	BAD_CHECKSUM,
	BAD_LENGTH,
	ERROR,
	EDGE_COUNT,
};
static rte_edge_t edges[UINT_NUM_VALUES(uint8_t)] = {UNKNOWN_PROTO};

void ip6_input_local_add_proto(uint8_t proto, const char *next_node) {
	LOG(DEBUG, "ip6_input_local: proto=%hhu -> %s", proto, next_node);
	if (edges[proto] != UNKNOWN_PROTO)
		ABORT("next node already registered for proto=%hhu", proto);
	edges[proto] = gr_node_attach_parent("ip6_input_local", next_node);
}

static uint16_t ip6_input_local_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct ip6_local_mbuf_data *d;
	const struct iface *iface;
	struct rte_ipv6_hdr *ip;
	struct rte_mbuf *m;
	rte_edge_t edge;
	uint16_t i;

	for (i = 0; i < nb_objs; i++) {
		m = objs[i];
		ip = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);

		if (gr_mbuf_is_traced(m))
			gr_mbuf_trace_add(m, node, 0);

		// prepare ip local data
		iface = l3_mbuf_data(m)->iface;
		d = ip6_local_mbuf_data(m);
		d->src = ip->src_addr;
		d->dst = ip->dst_addr;
		d->len = rte_be_to_cpu_16(ip->payload_len);
		d->hop_limit = ip->hop_limits;
		d->proto = ip->proto;
		d->iface = iface;
		d->ext_offset = sizeof(*ip);

		if (rte_pktmbuf_data_len(m) < sizeof(*ip) + d->len) {
			edge = BAD_LENGTH;
			goto next;
		}

		// advance through IPv6 extension headers until we find a registered handler
		while ((edge = edges[d->proto]) == UNKNOWN_PROTO) {
			size_t ext_size = 0;
			const uint8_t *ext;
			uint8_t _ext[2];
			int next_proto;

			ext = rte_pktmbuf_read(m, d->ext_offset, sizeof(_ext), _ext);
			if (ext == NULL) {
				edge = ERROR;
				goto next;
			}
			next_proto = rte_ipv6_get_next_ext(ext, d->proto, &ext_size);
			if (next_proto < 0)
				break; // end of extension headers
			// the extensions must fit in the announced payload
			if (d->len < ext_size) {
				edge = BAD_LENGTH;
				goto next;
			}
			d->ext_offset += ext_size;
			d->len -= ext_size;
			d->proto = next_proto;
		};

		if (edge == UNKNOWN_PROTO)
			goto next;

		m->packet_type = RTE_PTYPE_L3_IPV6;

		switch (d->proto) {
		case IPPROTO_AH:
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		case IPPROTO_FRAGMENT:
			// IPv6 extensions are L3 and need the IPv6 header.
			goto next;
		case IPPROTO_UDP:
		case IPPROTO_TCP:
		case IPPROTO_SCTP:
		case IPPROTO_DCCP:
			// These protocols have checksum fields to be verified.
			break;
		default:
			// No checksum to verify.
			goto adj_next;
		}

		// verify checksum if not already checked by hardware
		switch (m->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) {
		case RTE_MBUF_F_RX_L4_CKSUM_NONE:
		case RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN:
			if (rte_ipv6_udptcp_cksum_verify(
				    ip, rte_pktmbuf_mtod_offset(m, void *, d->ext_offset)
			    )) {
				edge = BAD_CHECKSUM;
				goto next;
			}
			break;
		case RTE_MBUF_F_RX_L4_CKSUM_BAD:
			edge = BAD_CHECKSUM;
			goto next;
		}

adj_next:
		rte_pktmbuf_adj(m, d->ext_offset);
		d->ext_offset = 0;
next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static struct rte_node_register input_node = {
	.name = "ip6_input_local",
	.process = ip6_input_local_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[UNKNOWN_PROTO] = "ip6_input_local_unknown_proto",
		[BAD_CHECKSUM] = "ip6_input_local_bad_checksum",
		[BAD_LENGTH] = "ip6_input_local_bad_length",
		[ERROR] = "ip6_input_local_error",
	},
};

static struct gr_node_info info = {
	.node = &input_node,
	.type = GR_NODE_T_L3,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(ip6_input_local_unknown_proto);
GR_DROP_REGISTER(ip6_input_local_bad_checksum);
GR_DROP_REGISTER(ip6_input_local_bad_length);
GR_DROP_REGISTER(ip6_input_local_error);

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
#define TEST_PROTO IPPROTO_ICMPV6
#define TEST_PAYLOAD_LEN 8

struct fake_mbuf {
	struct rte_ipv6_hdr ipv6_hdr;
	uint8_t payload[64];
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static struct iface test_iface;

static void fake_mbuf_init(struct fake_mbuf *fm) {
	memset(fm, 0, sizeof(*fm));

	fm->ipv6_hdr.vtc_flow = rte_cpu_to_be_32(6 << 28);
	fm->ipv6_hdr.payload_len = rte_cpu_to_be_16(TEST_PAYLOAD_LEN);
	fm->ipv6_hdr.proto = TEST_PROTO;
	fm->ipv6_hdr.hop_limits = 64;
	memset(&fm->ipv6_hdr.src_addr, 0x11, sizeof(fm->ipv6_hdr.src_addr));
	memset(&fm->ipv6_hdr.dst_addr, 0x22, sizeof(fm->ipv6_hdr.dst_addr));

	fm->mbuf.buf_addr = &fm->ipv6_hdr;
	fm->mbuf.data_len = sizeof(fm->ipv6_hdr) + TEST_PAYLOAD_LEN;
	fm->mbuf.pkt_len = fm->mbuf.data_len;
	fm->mbuf.nb_segs = 1;

	l3_mbuf_data(&fm->mbuf)->iface = &test_iface;
}

static int setup(void **) {
	edges[TEST_PROTO] = TEST_EDGE;
	return 0;
}

// A payload length announcing more than the packet carries.
static void ip6_local_payload_len_beyond_mbuf(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	fm.ipv6_hdr.payload_len = rte_cpu_to_be_16(TEST_PAYLOAD_LEN + 1);

	expect_uint_value(rte_node_enqueue_x1, next, BAD_LENGTH);
	ip6_input_local_process(NULL, NULL, &obj, 1);
}

// An extension header larger than the announced payload would make the
// remaining length underflow as the walk subtracts it.
static void ip6_local_ext_beyond_payload_len(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	fm.mbuf.data_len = fm.mbuf.pkt_len = sizeof(fm.ipv6_hdr) + sizeof(fm.payload);
	// One hop by hop options header, which rte_ipv6_get_next_ext() sizes at
	// 8 bytes, while the payload claims to be shorter than that.
	fm.ipv6_hdr.proto = IPPROTO_HOPOPTS;
	fm.ipv6_hdr.payload_len = rte_cpu_to_be_16(4);
	fm.payload[0] = TEST_PROTO;
	fm.payload[1] = 0;

	expect_uint_value(rte_node_enqueue_x1, next, BAD_LENGTH);
	ip6_input_local_process(NULL, NULL, &obj, 1);
}

// Only the first segment can be read contiguously, which is what every node
// below does, so a payload that reaches into the next one is refused.
static void ip6_local_payload_len_beyond_first_segment(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	fm.mbuf.data_len = sizeof(fm.ipv6_hdr) + TEST_PAYLOAD_LEN / 2;
	fm.mbuf.pkt_len = sizeof(fm.ipv6_hdr) + TEST_PAYLOAD_LEN;
	fm.mbuf.nb_segs = 2;

	expect_uint_value(rte_node_enqueue_x1, next, BAD_LENGTH);
	ip6_input_local_process(NULL, NULL, &obj, 1);
}

// Trailing bytes beyond the announced payload are valid.
static void ip6_local_payload_len_below_mbuf(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	fm.mbuf.data_len = fm.mbuf.pkt_len = sizeof(fm.ipv6_hdr) + sizeof(fm.payload);

	expect_uint_value(rte_node_enqueue_x1, next, TEST_EDGE);
	ip6_input_local_process(NULL, NULL, &obj, 1);

	assert_int_equal(ip6_local_mbuf_data(&fm.mbuf)->len, TEST_PAYLOAD_LEN);
}

static void ip6_local_valid_length(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, TEST_EDGE);
	ip6_input_local_process(NULL, NULL, &obj, 1);

	assert_int_equal(ip6_local_mbuf_data(&fm.mbuf)->len, TEST_PAYLOAD_LEN);
}

// l4_loopback_output picks the address family from the packet type, so a
// protocol with no checksum to verify needs it set just the same.
static void ip6_local_sets_packet_type(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm);
	assert_int_not_equal(fm.mbuf.packet_type, RTE_PTYPE_L3_IPV6);

	expect_uint_value(rte_node_enqueue_x1, next, TEST_EDGE);
	ip6_input_local_process(NULL, NULL, &obj, 1);

	assert_int_equal(fm.mbuf.packet_type, RTE_PTYPE_L3_IPV6);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(ip6_local_payload_len_beyond_mbuf, setup),
		cmocka_unit_test_setup(ip6_local_payload_len_beyond_first_segment, setup),
		cmocka_unit_test_setup(ip6_local_ext_beyond_payload_len, setup),
		cmocka_unit_test_setup(ip6_local_payload_len_below_mbuf, setup),
		cmocka_unit_test_setup(ip6_local_valid_length, setup),
		cmocka_unit_test_setup(ip6_local_sets_packet_type, setup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
