// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "clock.h"
#include "control_output.h"
#include "graph.h"
#include "icmp6.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "log.h"
#include "mbuf.h"
#include "trace.h"

enum {
	ICMP6_OUTPUT = 0,
	NEIGH_SOLICIT,
	NEIGH_ADVERT,
	ROUTER_SOLICIT,
	ROUTER_ADVERT,
	CONTROL,
	BAD_CHECKSUM,
	INVALID,
	UNSUPPORTED,
	NO_LOCAL_ADDR,
	EDGE_COUNT,
};

static control_queue_cb_t icmp6_cb[UINT8_MAX];

// RFC 4443 2.3: the checksum covers a pseudo header made of the addresses, the
// upper layer packet length and the ICMPv6 next header value.
static inline int icmp6_cksum_verify(const struct ip6_local_mbuf_data *d, const void *icmp6) {
	const struct rte_ipv6_hdr phdr = {
		.payload_len = rte_cpu_to_be_16(d->len),
		.proto = IPPROTO_ICMPV6,
		.src_addr = d->src,
		.dst_addr = d->dst,
	};

	return rte_ipv6_udptcp_cksum_verify(&phdr, icmp6);
}

// RFC 4443 2.1: error messages are the types with the high order bit clear.
// They all quote the invoking packet, of which at least its IPv6 header fits.
static inline bool icmp6_is_error(uint8_t type) {
	return (type & 0x80) == 0;
}

static uint16_t
icmp6_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip6_local_mbuf_data *d;
	struct icmp6 *icmp6;
	struct rte_ipv6_addr tmp_ip;
	struct rte_mbuf *mbuf;
	rte_edge_t next;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		icmp6 = rte_pktmbuf_mtod(mbuf, struct icmp6 *);
		d = ip6_local_mbuf_data(mbuf);

		if (gr_mbuf_is_traced(mbuf)) {
			uint8_t trace_len = RTE_MIN(d->len, GR_TRACE_ITEM_MAX_LEN);
			struct icmp6 *t = gr_mbuf_trace_add(mbuf, node, trace_len);
			memcpy(t, icmp6, trace_len);
		}

		if (d->len < GR_ICMP6_HDR_LEN) {
			next = INVALID;
			goto next;
		}
		if (icmp6_cksum_verify(d, icmp6) < 0) {
			next = BAD_CHECKSUM;
			goto next;
		}

		switch (icmp6->type) {
		case ICMP6_TYPE_ECHO_REQUEST:
			if (icmp6->code != 0) {
				next = INVALID;
				goto next;
			}
			icmp6->type = ICMP6_TYPE_ECHO_REPLY;
			if (rte_ipv6_addr_is_mcast(&d->dst)) {
				struct nexthop *local = addr6_get_linklocal(
					mbuf_data(mbuf)->iface->id
				);
				if (local == NULL) {
					next = NO_LOCAL_ADDR;
					goto next;
				}
				tmp_ip = nexthop_info_l3(local)->ipv6;
			} else {
				// swap source/destination addresses
				tmp_ip = d->dst;
			}
			d->dst = d->src;
			d->src = tmp_ip;
			next = ICMP6_OUTPUT;
			break;
		case ICMP6_TYPE_NEIGH_SOLICIT:
			next = NEIGH_SOLICIT;
			break;
		case ICMP6_TYPE_NEIGH_ADVERT:
			next = NEIGH_ADVERT;
			break;
		case ICMP6_TYPE_ROUTER_SOLICIT:
			next = ROUTER_SOLICIT;
			break;
		case ICMP6_TYPE_ROUTER_ADVERT:
			// Grout does not process router advertisements itself.
			// Punt them to the control plane so that a routing daemon
			// (e.g. FRR) running on top of grout can consume them. BGP
			// unnumbered peering relies on received RAs to discover the
			// peer link-local next hop; without this the packets would
			// be dropped as unsupported and the session would never come
			// up.
			next = ROUTER_ADVERT;
			break;
		default:
			if (icmp6_cb[icmp6->type] != NULL) {
				if (icmp6_is_error(icmp6->type)
				    && d->len < GR_ICMP6_HDR_LEN + sizeof(struct rte_ipv6_hdr)) {
					next = INVALID;
					goto next;
				}
				control_output_set_cb(mbuf, icmp6_cb[icmp6->type], clock_ns());
				next = CONTROL;
			} else {
				next = UNSUPPORTED;
			}
		}
next:
		rte_node_enqueue_x1(graph, node, next, mbuf);
	}

	return nb_objs;
}

void icmp6_input_register_callback(uint8_t icmp6_type, control_queue_cb_t cb) {
	if (icmp6_type == ICMP6_TYPE_ECHO_REQUEST)
		ABORT("cannot register callback for echo request");
	if (icmp6_cb[icmp6_type])
		ABORT("callback already registered for %d", icmp6_type);

	icmp6_cb[icmp6_type] = cb;
}

static void icmp6_input_register(void) {
	ip6_input_local_add_proto(IPPROTO_ICMPV6, "icmp6_input");
}

static struct rte_node_register icmp6_input_node = {
	.name = "icmp6_input",

	.process = icmp6_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[ICMP6_OUTPUT] = "icmp6_output",
		[NEIGH_SOLICIT] = "ndp_ns_input",
		[NEIGH_ADVERT] = "ndp_na_input",
		[ROUTER_SOLICIT] = "ndp_rs_input",
		[ROUTER_ADVERT] = "ndp_ra_input",
		[CONTROL] = "control_output",
		[BAD_CHECKSUM] = "icmp6_input_bad_checksum",
		[INVALID] = "icmp6_input_invalid",
		[UNSUPPORTED] = "icmp6_input_unsupported",
		[NO_LOCAL_ADDR] = "icmp6_input_no_local_addr",
	},
};

static struct gr_node_info icmp6_input_info = {
	.node = &icmp6_input_node,
	.type = GR_NODE_T_CONTROL | GR_NODE_T_L4,
	.register_callback = icmp6_input_register,
	.trace_format = (gr_trace_format_cb_t)trace_icmp6_format,
};

GR_NODE_REGISTER(icmp6_input_info);

GR_DROP_REGISTER(icmp6_input_bad_checksum);
GR_DROP_REGISTER(icmp6_input_invalid);
GR_DROP_REGISTER(icmp6_input_unsupported);
GR_DROP_REGISTER(icmp6_input_no_local_addr);

#ifdef __GROUT_UNIT_TEST__
#include "_cmocka.h"

#include <stddef.h>

int gr_rte_log_type;
struct log_types log_types = STAILQ_HEAD_INITIALIZER(log_types);
struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);
mock_func(rte_edge_t, gr_node_attach_parent(const char *, const char *));
mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(void, ip6_input_local_add_proto(uint8_t, const char *));
mock_func(rte_edge_t, gr_control_input_register_handler(const char *));
mock_func(int, post_to_stack(rte_edge_t, struct rte_mbuf *));
mock_func(struct iface *, get_vrf_iface(uint16_t));
mock_func(bool, addr6_is_local_on_iface(uint16_t, const struct rte_ipv6_addr *));
mock_func(struct nexthop *, addr6_get_linklocal(uint16_t));

// Referenced by the inline helpers in clock.h and control_output.h.
__thread gr_clock_ns_t clock_snapshot_ns;
__thread bool clock_trusted;
int cq_callback_offset;
int cq_priv_offset;
mock_func(int, trace_icmp6_format(char *, size_t, const struct icmp6 *, size_t));

#define TEST_PAYLOAD_LEN 8

struct fake_mbuf {
	struct icmp6 icmp6;
	uint8_t payload[64];
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static struct iface test_iface;

static void test_cb(void *, uintptr_t, const struct control_queue_drain *) { }

static int setup(void **) {
	// Dynamic fields live inside the mbuf reserved area, as in a real one.
	cq_callback_offset = offsetof(struct rte_mbuf, dynfield1);
	cq_priv_offset = cq_callback_offset + sizeof(control_queue_cb_t);
	icmp6_cb[ICMP6_ERR_PKT_TOO_BIG] = test_cb;
	return 0;
}

static void fake_mbuf_init(struct fake_mbuf *fm, uint8_t type, uint16_t len) {
	struct ip6_local_mbuf_data *d;

	memset(fm, 0, sizeof(*fm));

	fm->icmp6.type = type;
	fm->icmp6.code = 0;

	fm->mbuf.buf_addr = &fm->icmp6;
	fm->mbuf.data_len = sizeof(fm->icmp6) + sizeof(fm->payload);
	fm->mbuf.pkt_len = fm->mbuf.data_len;
	fm->mbuf.nb_segs = 1;

	d = ip6_local_mbuf_data(&fm->mbuf);
	memset(&d->src, 0x11, sizeof(d->src));
	memset(&d->dst, 0x22, sizeof(d->dst));
	d->len = len;
	d->hop_limit = 64;
	d->proto = IPPROTO_ICMPV6;
	d->iface = &test_iface;
}

// Fill in the checksum the node expects for the message as it stands.
static void fake_mbuf_cksum(struct fake_mbuf *fm) {
	const struct ip6_local_mbuf_data *d = ip6_local_mbuf_data(&fm->mbuf);
	const struct rte_ipv6_hdr phdr = {
		.payload_len = rte_cpu_to_be_16(d->len),
		.proto = IPPROTO_ICMPV6,
		.src_addr = d->src,
		.dst_addr = d->dst,
	};

	fm->icmp6.cksum = 0;
	fm->icmp6.cksum = rte_ipv6_udptcp_cksum(&phdr, &fm->icmp6);
}

// RFC 4443: every ICMPv6 message carries the 4 byte preamble and a 4 byte
// body. Spell the minimum out rather than reuse the constant the node tests
// against, so that the bound itself is checked and not just the comparison.
#define ICMP6_RFC_MIN_LEN 8

static void icmp6_input_too_short(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, ICMP6_TYPE_ECHO_REQUEST, ICMP6_RFC_MIN_LEN - 1);
	fake_mbuf_cksum(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, INVALID);
	icmp6_input_process(NULL, NULL, &obj, 1);
}

// The shortest message the RFC allows must go through.
static void icmp6_input_shortest_valid(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, ICMP6_TYPE_ECHO_REQUEST, ICMP6_RFC_MIN_LEN);
	fake_mbuf_cksum(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, ICMP6_OUTPUT);
	icmp6_input_process(NULL, NULL, &obj, 1);
}

static void icmp6_input_bad_cksum(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, ICMP6_TYPE_ECHO_REQUEST, sizeof(struct icmp6) + TEST_PAYLOAD_LEN);
	fake_mbuf_cksum(&fm);
	fm.icmp6.cksum = ~fm.icmp6.cksum;

	expect_uint_value(rte_node_enqueue_x1, next, BAD_CHECKSUM);
	icmp6_input_process(NULL, NULL, &obj, 1);
}

// A well formed echo request is answered by the datapath.
static void icmp6_input_echo_request(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, ICMP6_TYPE_ECHO_REQUEST, sizeof(struct icmp6) + TEST_PAYLOAD_LEN);
	fake_mbuf_cksum(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, ICMP6_OUTPUT);
	icmp6_input_process(NULL, NULL, &obj, 1);

	assert_int_equal(fm.icmp6.type, ICMP6_TYPE_ECHO_REPLY);
}

// RFC 4443: the 8 byte error header plus the invoking IPv6 header. Spelled
// out on purpose, see icmp6_input_too_short().
#define ICMP6_ERROR_MIN_LEN 48

// RFC 4443: an error message quotes at least the IPv6 header of the packet
// that caused it.
static void icmp6_input_error_too_short(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, ICMP6_ERR_PKT_TOO_BIG, ICMP6_ERROR_MIN_LEN - 1);
	fake_mbuf_cksum(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, INVALID);
	icmp6_input_process(NULL, NULL, &obj, 1);
}

static void icmp6_input_error_valid(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, ICMP6_ERR_PKT_TOO_BIG, ICMP6_ERROR_MIN_LEN);
	fake_mbuf_cksum(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, CONTROL);
	icmp6_input_process(NULL, NULL, &obj, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(icmp6_input_too_short, setup),
		cmocka_unit_test_setup(icmp6_input_shortest_valid, setup),
		cmocka_unit_test_setup(icmp6_input_bad_cksum, setup),
		cmocka_unit_test_setup(icmp6_input_echo_request, setup),
		cmocka_unit_test_setup(icmp6_input_error_too_short, setup),
		cmocka_unit_test_setup(icmp6_input_error_valid, setup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
