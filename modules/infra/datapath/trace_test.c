// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Harrison Caldicott

#include "_cmocka.h"
#include "trace.c"

#include <rte_eal.h>

// mocked types/functions
int gr_rte_log_type;
struct log_types log_types = STAILQ_HEAD_INITIALIZER(log_types);
struct workers workers = STAILQ_HEAD_INITIALIZER(workers);
void module_register(struct module *) { }
const struct gr_node_info *gr_node_info_get(rte_node_t) {
	return NULL;
}

// Pool sized so a single packet can exhaust it. Optimal mempool sizes are
// 2^n - 1.
#define TRACE_TEST_POOL_SIZE 7

static struct test_mbuf {
	struct rte_mbuf m;
	uint8_t priv[GR_MBUF_PRIV_MAX_SIZE];
} pkt;

static struct rte_node fake_node;

static int setup(void **) {
	trace_pool = rte_mempool_create(
		"trace_test_items",
		TRACE_TEST_POOL_SIZE,
		sizeof(struct gr_trace_item),
		0, // cache size
		0, // priv size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		SOCKET_ID_ANY,
		0 // flags
	);
	if (trace_pool == NULL)
		return -1;
	traced_packets = rte_ring_create(
		"trace_test_packets", 8, SOCKET_ID_ANY, RING_F_MP_RTS_ENQ | RING_F_MC_RTS_DEQ
	);
	if (traced_packets == NULL)
		return -1;
	return 0;
}

static int teardown(void **) {
	rte_ring_free(traced_packets);
	rte_mempool_free(trace_pool);
	return 0;
}

// All trace items are attached to a single in-flight packet: the
// traced_packets ring is empty and nothing can be reclaimed. The next
// allocation must abandon tracing for the packet instead of spinning forever.
static void exhausted_pool_does_not_deadlock(void **) {
	STAILQ_INIT(gr_mbuf_traces(&pkt.m));

	for (unsigned i = 0; i < TRACE_TEST_POOL_SIZE; i++)
		assert_non_null(gr_mbuf_trace_add(&pkt.m, &fake_node, 0));

	assert_int_equal(rte_mempool_avail_count(trace_pool), 0);
	assert_non_null(gr_mbuf_trace_add(&pkt.m, &fake_node, 0));

	// Tracing for the packet was abandoned and its chain returned to the pool.
	assert_true(STAILQ_EMPTY(gr_mbuf_traces(&pkt.m)));
	assert_int_equal(rte_mempool_avail_count(trace_pool), TRACE_TEST_POOL_SIZE);
}

// When completed traces sit in the ring, exhaustion is resolved by recycling
// the oldest completed trace, not by abandoning the current packet.
static void exhausted_pool_recycles_completed_traces(void **) {
	struct test_mbuf done;

	STAILQ_INIT(gr_mbuf_traces(&done.m));
	assert_non_null(gr_mbuf_trace_add(&done.m, &fake_node, 0));
	gr_mbuf_trace_finish(&done.m);

	STAILQ_INIT(gr_mbuf_traces(&pkt.m));
	for (unsigned i = 0; i < TRACE_TEST_POOL_SIZE - 1; i++)
		assert_non_null(gr_mbuf_trace_add(&pkt.m, &fake_node, 0));

	assert_int_equal(rte_mempool_avail_count(trace_pool), 0);
	assert_non_null(gr_mbuf_trace_add(&pkt.m, &fake_node, 0));

	// The current packet kept its full chain by stealing the completed trace.
	assert_false(STAILQ_EMPTY(gr_mbuf_traces(&pkt.m)));
	assert_int_equal(rte_mempool_avail_count(trace_pool), 0);
}

// The abandon path is also reachable from gr_mbuf_trace_copy() via
// gr_mbuf_copy(): when the pool runs out mid-copy and nothing can be
// recycled, the partial copy must be freed and the source chain left intact.
static void exhausted_pool_abandons_trace_copy(void **) {
	struct gr_trace_item *trace;
	struct test_mbuf copy;
	unsigned count;

	STAILQ_INIT(gr_mbuf_traces(&pkt.m));
	for (unsigned i = 0; i < TRACE_TEST_POOL_SIZE - 2; i++)
		assert_non_null(gr_mbuf_trace_add(&pkt.m, &fake_node, 0));

	// Two free items remain: the copy exhausts the pool mid-chain.
	gr_mbuf_trace_copy(&copy.m, &pkt.m);

	// The partial copy was abandoned and its items returned to the pool.
	assert_true(STAILQ_EMPTY(gr_mbuf_traces(&copy.m)));
	assert_int_equal(rte_mempool_avail_count(trace_pool), 2);

	// The source chain was not touched.
	count = 0;
	STAILQ_FOREACH (trace, gr_mbuf_traces(&pkt.m), next)
		count++;
	assert_int_equal(count, TRACE_TEST_POOL_SIZE - 2);
}

int main(void) {
	char arg0[] = "trace_test";
	char arg1[] = "--no-huge";
	char arg2[] = "--in-memory";
	char arg3[] = "--lcores=0";
	char arg4[] = "--no-pci";
	char arg5[] = "--log-level=*:error";
	char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5};

	if (rte_eal_init(ARRAY_DIM(argv), argv) < 0)
		return 1;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(exhausted_pool_does_not_deadlock, setup, teardown),
		cmocka_unit_test_setup_teardown(
			exhausted_pool_recycles_completed_traces, setup, teardown
		),
		cmocka_unit_test_setup_teardown(
			exhausted_pool_abandons_trace_copy, setup, teardown
		),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
