// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "datapath.h"
#include "graph.h"
#include "ip4_datapath.h"
#include "mbuf.h"
#include "trace.h"

#include <rte_icmp.h>

GR_NODE_CTX_TYPE(icmp_input_ctx, { struct rate_limit_ctx limit; });

enum {
	OUTPUT = 0,
	DELIVER,
	INVALID,
	UNSUPPORTED,
	RATE_LIMITED,
	IGNORED,
	EDGE_COUNT,
};

#define ICMP_MIN_SIZE 8

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
	struct icmp_input_ctx *ctx = icmp_input_ctx(node);
	struct ip_local_mbuf_data *ip_data;
	struct rte_icmp_hdr *icmp;
	const struct iface *iface;
	struct rte_mbuf *mbuf;
	rte_edge_t edge;
	uint16_t cksum;
	ip4_addr_t ip;

	if (rate_limited(&ctx->limit, graph_conf.icmp_rate, nb_objs)) {
		rte_node_next_stream_move(graph, node, RATE_LIMITED);
		return nb_objs;
	}

	for (uint16_t i = 0; i < nb_objs; i++) {
		mbuf = objs[i];
		icmp = rte_pktmbuf_mtod(mbuf, struct rte_icmp_hdr *);
		ip_data = ip_local_mbuf_data(mbuf);
		cksum = ~rte_raw_cksum(icmp, ip_data->len);

		if (ip_data->len < ICMP_MIN_SIZE || cksum) {
			edge = INVALID;
			goto next;
		}

		switch (icmp->icmp_type) {
		case RTE_ICMP_TYPE_ECHO_REQUEST:
			if (icmp->icmp_code != 0) {
				edge = INVALID;
				goto next;
			}
			iface = mbuf_data(mbuf)->iface;
			assert(iface != NULL);
			if (iface->flags & GR_IFACE_F_PING_IGNORE) {
				edge = IGNORED;
				goto next;
			}
			icmp->icmp_type = RTE_ICMP_TYPE_ECHO_REPLY;
			ip = ip_data->dst;
			ip_data->dst = ip_data->src;
			ip_data->src = ip;
			edge = OUTPUT;
			break;
		case RTE_ICMP_TYPE_DEST_UNREACHABLE:
		case RTE_ICMP_TYPE_TTL_EXCEEDED:
		case RTE_ICMP_TYPE_PARAM_PROBLEM:
		case RTE_ICMP_TYPE_ECHO_REPLY:
			if (icmp_quotes_datagram(icmp->icmp_type)
			    && !icmp_quoted_datagram_valid(icmp, ip_data->len)) {
				edge = INVALID;
				goto next;
			}
			edge = DELIVER;
			break;
		default:
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

static int icmp_input_init(const struct rte_graph *, struct rte_node *node) {
	struct icmp_input_ctx *ctx = icmp_input_ctx(node);
	ctx->limit.tokens = graph_conf.icmp_rate;
	ctx->limit.last_refill = rte_rdtsc();
	return 0;
}

static void icmp_input_register(void) {
	ip_input_local_add_proto(IPPROTO_ICMP, "icmp_input");
}

static struct rte_node_register icmp_input_node = {
	.name = "icmp_input",

	.process = icmp_input_process,
	.init = icmp_input_init,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "icmp_output",
		[DELIVER] = "icmp_input_deliver",
		[INVALID] = "icmp_input_invalid",
		[UNSUPPORTED] = "icmp_input_unsupported",
		[RATE_LIMITED] = "error_rate_limited",
		[IGNORED] = "ping_ignored",
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
GR_DROP_REGISTER(ping_ignored);

#ifdef __GROUT_UNIT_TEST__
#include "_cmocka.h"
#include "log.h"

#include <stddef.h>

int gr_rte_log_type;
struct gr_graph_conf graph_conf;
struct log_types log_types = STAILQ_HEAD_INITIALIZER(log_types);
struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);
mock_func(rte_edge_t, gr_node_attach_parent(const char *, const char *));
mock_func(void *, gr_mbuf_trace_add(struct rte_mbuf *, struct rte_node *, size_t));
mock_func(uint16_t, drop_packets(struct rte_graph *, struct rte_node *, void **, uint16_t));
mock_func(int, drop_format(char *, size_t, const void *, size_t));
mock_func(void, ip_input_local_add_proto(uint8_t, const char *));
mock_func(int, trace_icmp_format(char *, size_t, const struct rte_icmp_hdr *, size_t));

struct fake_mbuf {
	struct rte_icmp_hdr icmp;
	struct rte_ipv4_hdr inner_ip;
	uint8_t inner_data[ICMP_QUOTED_DATA_LEN];
	struct rte_mbuf mbuf;
	uint8_t priv_data[GR_MBUF_PRIV_MAX_SIZE];
};

static struct iface dummy_iface;

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
	d->iface = &dummy_iface;
	d->src = RTE_IPV4(192, 168, 0, 1);
	d->dst = RTE_IPV4(192, 168, 0, 2);
	d->len = len;
	d->ttl = 64;
	d->proto = IPPROTO_ICMP;
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

	expect_uint_value(rte_node_enqueue_x1, next, DELIVER);
	icmp_input_process(NULL, NULL, &obj, 1);
}

#define TEST_HZ 1000000
#define TEST_RATE 1000
#define TEST_TOKEN_TICKS (TEST_HZ / TEST_RATE)

static void rate_limit_refill(void **) {
	struct rate_limit_ctx ctx = {0};
	unsigned taken = 0;
	uint64_t now;

	assert_false(rate_limited_at(&ctx, 0, RTE_GRAPH_BURST_SIZE, 0, TEST_HZ));

	assert_true(rate_limited_at(&ctx, TEST_RATE, 1, TEST_TOKEN_TICKS - 1, TEST_HZ));
	assert_false(rate_limited_at(&ctx, TEST_RATE, 1, TEST_TOKEN_TICKS, TEST_HZ));
	assert_true(rate_limited_at(&ctx, TEST_RATE, 1, TEST_TOKEN_TICKS + 1, TEST_HZ));

	ctx = (struct rate_limit_ctx) {0};
	for (now = 0; now <= TEST_HZ; now += TEST_TOKEN_TICKS * 19 / 10) {
		while (!rate_limited_at(&ctx, TEST_RATE, 1, now, TEST_HZ))
			taken++;
	}
	assert_in_range(taken, TEST_RATE - 2, TEST_RATE);
}

static void rate_limit_idle(void **) {
	struct rate_limit_ctx ctx = {0};

	assert_false(rate_limited_at(&ctx, TEST_RATE, 1, 131100ULL * TEST_TOKEN_TICKS, TEST_HZ));
	assert_int_equal(ctx.tokens, TEST_RATE - 1);

	ctx = (struct rate_limit_ctx) {0};
	assert_false(rate_limited_at(&ctx, UINT16_MAX, 1, UINT64_MAX / 2, TEST_HZ));
	assert_int_equal(ctx.tokens, UINT16_MAX - 1);
}

static void rate_limit_vector(void **) {
	struct rate_limit_ctx ctx = {.tokens = 10};

	assert_false(rate_limited_at(&ctx, TEST_RATE, RTE_GRAPH_BURST_SIZE, 0, TEST_HZ));
	assert_int_equal(ctx.tokens, 0);
	assert_true(rate_limited_at(&ctx, TEST_RATE, RTE_GRAPH_BURST_SIZE, 0, TEST_HZ));

	ctx = (struct rate_limit_ctx) {.tokens = TEST_RATE};
	assert_false(rate_limited_at(&ctx, 10, 1, TEST_HZ / 10, TEST_HZ));
	assert_int_equal(ctx.tokens, 10 - 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(icmp_input_too_short),
		cmocka_unit_test(icmp_input_bad_cksum),
		cmocka_unit_test(icmp_input_echo_request),
		cmocka_unit_test(icmp_input_error_too_short),
		cmocka_unit_test(icmp_input_error_inner_ihl_too_long),
		cmocka_unit_test(icmp_input_error_valid),
		cmocka_unit_test(rate_limit_refill),
		cmocka_unit_test(rate_limit_idle),
		cmocka_unit_test(rate_limit_vector),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
