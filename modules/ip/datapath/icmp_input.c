// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "clock.h"
#include "control_output.h"
#include "graph.h"
#include "ip4_datapath.h"
#include "log.h"
#include "mbuf.h"
#include "trace.h"

#include <rte_icmp.h>

enum {
	OUTPUT = 0,
	CONTROL,
	INVALID,
	UNSUPPORTED,
	EDGE_COUNT,
};

#define ICMP_MIN_SIZE 8

static control_queue_cb_t icmp_cb[UINT8_MAX];

// RFC 792: the number of bytes of the datagram in error that an ICMP error
// message carries after the quoted IP header.
#define ICMP_QUOTED_DATA_LEN 8

// Source quench belongs here too, deprecated by RFC 6633 and never punted.
static inline bool icmp_quotes_datagram(uint8_t type) {
	switch (type) {
	case RTE_ICMP_TYPE_DEST_UNREACHABLE:
	case RTE_ICMP_TYPE_REDIRECT:
	case RTE_ICMP_TYPE_TTL_EXCEEDED:
	case RTE_ICMP_TYPE_PARAM_PROBLEM:
		return true;
	default:
		return false;
	}
}

// RFC 792: an error message carries its own header, the header of the datagram
// in error and the next 64 bits of it.
static inline bool icmp_quoted_datagram_valid(const struct rte_icmp_hdr *icmp, uint16_t len) {
	const struct rte_ipv4_hdr *inner;

	if (len < sizeof(*icmp) + sizeof(*inner) + ICMP_QUOTED_DATA_LEN)
		return false;

	inner = PAYLOAD(icmp);

	return len >= sizeof(*icmp) + rte_ipv4_hdr_len(inner) + ICMP_QUOTED_DATA_LEN;
}

static uint16_t
icmp_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	struct ip_local_mbuf_data *ip_data;
	struct rte_icmp_hdr *icmp;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint16_t cksum;
	ip4_addr_t ip;

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		icmp = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr *);
		ip_data = ip_local_mbuf_data(mbuf);
		cksum = ~rte_raw_cksum(icmp, ip_data->len);

		if (ip_data->len < ICMP_MIN_SIZE || cksum) {
			edge = INVALID;
			goto next;
		}

		if (icmp->icmp_type == RTE_ICMP_TYPE_ECHO_REQUEST) {
			if (icmp->icmp_code != 0) {
				edge = INVALID;
				goto next;
			}
			icmp->icmp_type = RTE_ICMP_TYPE_ECHO_REPLY;
			ip = ip_data->dst;
			ip_data->dst = ip_data->src;
			ip_data->src = ip;
			edge = OUTPUT;
		} else if (icmp_cb[icmp->icmp_type]) {
			if (icmp_quotes_datagram(icmp->icmp_type)
			    && !icmp_quoted_datagram_valid(icmp, ip_data->len)) {
				edge = INVALID;
				goto next;
			}
			control_output_set_cb(mbuf, icmp_cb[icmp->icmp_type], clock_ns());
			edge = CONTROL;
		} else {
			edge = UNSUPPORTED;
		}
next:
		if (gr_mbuf_is_traced(mbuf)) {
			struct rte_icmp_hdr *d = gr_mbuf_trace_add(mbuf, node, sizeof(*d));
			*d = *icmp;
		}
		rte_node_enqueue_x1(graph, node, edge, mbuf);
	}

	return nb_objs;
}

void icmp_input_register_callback(uint8_t icmp_type, control_queue_cb_t cb) {
	if (icmp_type == RTE_ICMP_TYPE_ECHO_REQUEST)
		ABORT("cannot register callback for echo request");
	if (icmp_cb[icmp_type])
		ABORT("callback already registered for %d", icmp_type);

	icmp_cb[icmp_type] = cb;
}

static void icmp_input_register(void) {
	ip_input_local_add_proto(IPPROTO_ICMP, "icmp_input");
}

static struct rte_node_register icmp_input_node = {
	.name = "icmp_input",

	.process = icmp_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "icmp_output",
		[CONTROL] = "control_output",
		[INVALID] = "icmp_input_invalid",
		[UNSUPPORTED] = "icmp_input_unsupported",
	},
};

static struct gr_node_info icmp_input_info = {
	.node = &icmp_input_node,
	.type = GR_NODE_T_L4,
	.register_callback = icmp_input_register,
	.trace_format = (gr_trace_format_cb_t)trace_icmp_format,
};

GR_NODE_REGISTER(icmp_input_info);

GR_DROP_REGISTER(icmp_input_invalid);
GR_DROP_REGISTER(icmp_input_unsupported);

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
mock_func(void, ip_input_local_add_proto(uint8_t, const char *));
mock_func(rte_edge_t, gr_control_input_register_handler(const char *));
mock_func(int, post_to_stack(rte_edge_t, struct rte_mbuf *));
mock_func(struct iface *, get_vrf_iface(uint16_t));
mock_func(bool, addr4_is_local_on_iface(uint16_t, ip4_addr_t));
mock_func(int, trace_icmp_format(char *, size_t, const struct rte_icmp_hdr *, size_t));

// Referenced by the inline helpers in clock.h and control_output.h.
__thread gr_clock_ns_t clock_snapshot_ns;
__thread bool clock_trusted;
int cq_callback_offset;
int cq_priv_offset;

struct fake_mbuf {
	struct rte_icmp_hdr icmp;
	struct rte_ipv4_hdr inner_ip;
	uint8_t inner_data[ICMP_QUOTED_DATA_LEN];
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static struct iface test_iface;

static void test_cb(void *, uintptr_t, const struct control_queue_drain *) { }

static int setup(void **) {
	// Dynamic fields live inside the mbuf reserved area, as in a real one.
	cq_callback_offset = offsetof(struct rte_mbuf, dynfield1);
	cq_priv_offset = cq_callback_offset + sizeof(control_queue_cb_t);
	icmp_cb[RTE_ICMP_TYPE_TTL_EXCEEDED] = test_cb;
	return 0;
}

static void fake_mbuf_init(struct fake_mbuf *fm, uint8_t type, uint16_t len) {
	struct ip_local_mbuf_data *d;

	memset(fm, 0, sizeof(*fm));

	fm->icmp.icmp_type = type;
	fm->icmp.icmp_code = 0;

	fm->inner_ip.version = 4;
	fm->inner_ip.ihl = sizeof(fm->inner_ip) / 4;
	fm->inner_ip.next_proto_id = IPPROTO_TCP;

	fm->mbuf.buf_addr = &fm->icmp;
	fm->mbuf.data_len = sizeof(fm->icmp) + sizeof(fm->inner_ip) + sizeof(fm->inner_data);
	fm->mbuf.pkt_len = fm->mbuf.data_len;
	fm->mbuf.nb_segs = 1;

	d = ip_local_mbuf_data(&fm->mbuf);
	d->src = RTE_IPV4(192, 168, 0, 1);
	d->dst = RTE_IPV4(192, 168, 0, 2);
	d->len = len;
	d->ttl = 64;
	d->proto = IPPROTO_ICMP;
	d->iface = &test_iface;
}

static void fake_mbuf_cksum(struct fake_mbuf *fm) {
	uint16_t len = ip_local_mbuf_data(&fm->mbuf)->len;

	fm->icmp.icmp_cksum = 0;
	fm->icmp.icmp_cksum = ~rte_raw_cksum(&fm->icmp, len);
}

#define ICMP_ERROR_MIN_LEN                                                                         \
	(sizeof(struct rte_icmp_hdr) + sizeof(struct rte_ipv4_hdr) + ICMP_QUOTED_DATA_LEN)

static void icmp_input_too_short(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, RTE_ICMP_TYPE_ECHO_REQUEST, ICMP_MIN_SIZE - 1);
	fake_mbuf_cksum(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, INVALID);
	icmp_input_process(NULL, NULL, &obj, 1);
}

static void icmp_input_bad_cksum(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, RTE_ICMP_TYPE_ECHO_REQUEST, ICMP_ERROR_MIN_LEN);
	fake_mbuf_cksum(&fm);
	fm.icmp.icmp_cksum = ~fm.icmp.icmp_cksum;

	expect_uint_value(rte_node_enqueue_x1, next, INVALID);
	icmp_input_process(NULL, NULL, &obj, 1);
}

static void icmp_input_echo_request(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, RTE_ICMP_TYPE_ECHO_REQUEST, ICMP_ERROR_MIN_LEN);
	fake_mbuf_cksum(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, OUTPUT);
	icmp_input_process(NULL, NULL, &obj, 1);

	assert_int_equal(fm.icmp.icmp_type, RTE_ICMP_TYPE_ECHO_REPLY);
}

// RFC 792 wants the quoted header plus 64 bits of the datagram in error.
static void icmp_input_error_too_short(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, RTE_ICMP_TYPE_TTL_EXCEEDED, ICMP_ERROR_MIN_LEN - 1);
	fake_mbuf_cksum(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, INVALID);
	icmp_input_process(NULL, NULL, &obj, 1);
}

// A quoted header claiming options the message does not carry.
static void icmp_input_error_inner_ihl_too_long(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, RTE_ICMP_TYPE_TTL_EXCEEDED, ICMP_ERROR_MIN_LEN);
	fm.inner_ip.ihl = 15; // 60 bytes, way past the message
	fake_mbuf_cksum(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, INVALID);
	icmp_input_process(NULL, NULL, &obj, 1);
}

static void icmp_input_error_valid(void **) {
	struct fake_mbuf fm;
	void *obj = &fm.mbuf;

	fake_mbuf_init(&fm, RTE_ICMP_TYPE_TTL_EXCEEDED, ICMP_ERROR_MIN_LEN);
	fake_mbuf_cksum(&fm);

	expect_uint_value(rte_node_enqueue_x1, next, CONTROL);
	icmp_input_process(NULL, NULL, &obj, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(icmp_input_too_short, setup),
		cmocka_unit_test_setup(icmp_input_bad_cksum, setup),
		cmocka_unit_test_setup(icmp_input_echo_request, setup),
		cmocka_unit_test_setup(icmp_input_error_too_short, setup),
		cmocka_unit_test_setup(icmp_input_error_inner_ihl_too_long, setup),
		cmocka_unit_test_setup(icmp_input_error_valid, setup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
