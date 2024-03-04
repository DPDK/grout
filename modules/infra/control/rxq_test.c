// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "worker.h"

#include <br_api.h>
#include <br_cmocka.h>
#include <br_control.h>
#include <br_infra_msg.h>
#include <br_port.h>
#include <br_queue.h>
#include <br_stb_ds.h>
#include <br_worker.h>

#include <numa.h>

// tested functions
br_api_handler_func rxq_set;

// mocked types/functions
void br_register_api_handler(struct br_api_handler *);
void br_register_api_handler(struct br_api_handler *h) {
	switch (h->request_type) {
	case BR_INFRA_RXQ_SET:
		rxq_set = h->callback;
		break;
	}
}

int br_rte_log_type;
void br_register_module(struct br_module *) { }

mock_func(int, worker_graph_reload_all(void));
mock_func(int, port_reconfig(struct port *, uint16_t));
mock_func(int, port_destroy(uint16_t, struct port *));
mock_func(void, worker_graph_free(struct worker *));
mock_func(void *, br_datapath_loop(void *));
mock_func(void, __wrap_rte_free(void *));
mock_func(int, __wrap_pthread_create(pthread_t *, const pthread_attr_t *, void *(void *), void *));
mock_func(int, __wrap_pthread_join(pthread_t *, const pthread_attr_t *, void *(void *), void *));
mock_func(void *, __wrap_rte_zmalloc(char *, size_t, unsigned));
mock_func(unsigned, __wrap_rte_get_main_lcore(void));
mock_func(int, __wrap_numa_bitmask_isbitset(const struct bitmask *, int));

#define assert_api_out(expr, code, length)                                                         \
	do {                                                                                       \
		struct api_out out = expr;                                                         \
		assert_int_equal(out.status, code);                                                \
		assert_int_equal(out.len, length);                                                 \
	} while (0)

static void assign_rxq(struct worker *w, uint16_t port_id, uint16_t rxq_id) {
	struct queue_map qmap = {
		.port_id = port_id,
		.queue_id = rxq_id,
		.enabled = true,
	};
	arrpush(w->rxqs, qmap);
}

static void assign_txq(struct worker *w, uint16_t port_id, uint16_t txq_id) {
	struct queue_map qmap = {
		.port_id = port_id,
		.queue_id = txq_id,
		.enabled = true,
	};
	arrpush(w->txqs, qmap);
}

static struct port p0 = {.port_id = 0, .n_rxq = 2};
static struct port p1 = {.port_id = 1, .n_rxq = 2};
static struct port p2 = {.port_id = 2, .n_rxq = 2};
static struct worker w1 = {.cpu_id = 1, .started = true};
static struct worker w2 = {.cpu_id = 2, .started = true};
static struct worker w3 = {.cpu_id = 3, .started = true};

static int setup(void **) {
	LIST_INSERT_HEAD(&ports, &p0, next);
	LIST_INSERT_HEAD(&ports, &p1, next);
	LIST_INSERT_HEAD(&ports, &p2, next);

	LIST_INSERT_HEAD(&workers, &w1, next);
	assign_txq(&w1, 0, 0);
	assign_txq(&w1, 1, 0);
	assign_txq(&w1, 2, 0);

	assign_rxq(&w1, 0, 0);
	assign_rxq(&w1, 0, 1);
	assign_rxq(&w1, 1, 0);

	LIST_INSERT_HEAD(&workers, &w2, next);
	assign_txq(&w2, 0, 1);
	assign_txq(&w2, 1, 1);
	assign_txq(&w2, 2, 1);

	assign_rxq(&w2, 1, 1);
	assign_rxq(&w2, 2, 0);
	assign_rxq(&w2, 2, 1);

	return 0;
}

static int teardown(void **) {
	struct worker *w;
	LIST_FOREACH (w, &workers, next) {
		arrfree(w->rxqs);
		arrfree(w->txqs);
	}
	return 0;
}

static void rxq_set_main_lcore(void **) {
	struct br_infra_rxq_set_req req = {.cpu_id = 4};
	will_return(__wrap_rte_get_main_lcore, 4);
	assert_api_out(rxq_set(&req, NULL), EBUSY, 0);
}

static void rxq_set_invalid_cpu(void **) {
	struct br_infra_rxq_set_req req = {.cpu_id = 9999};
	will_return(__wrap_rte_get_main_lcore, 0);
	will_return(__wrap_numa_bitmask_isbitset, 0);
	assert_api_out(rxq_set(&req, NULL), ERANGE, 0);
}

static void common_mocks(void) {
	will_return_maybe(__wrap_rte_get_main_lcore, 0);
	will_return_maybe(__wrap_numa_bitmask_isbitset, 1);
	will_return_maybe(__wrap_pthread_join, 0);
	will_return_maybe(__wrap_rte_free, 0);
	will_return_maybe(worker_graph_free, 0);
	will_return_maybe(worker_graph_reload_all, 0);
}

static void rxq_set_invalid_port(void **) {
	struct br_infra_rxq_set_req req = {.cpu_id = 1, .port_id = 9999};
	common_mocks();
	assert_api_out(rxq_set(&req, NULL), ENODEV, 0);
}

static void rxq_set_invalid_rxq(void **) {
	struct br_infra_rxq_set_req req = {.cpu_id = 1, .port_id = 0, .rxq_id = 9999};
	common_mocks();
	assert_api_out(rxq_set(&req, NULL), ENODEV, 0);
}

static void rxq_set_already_set(void **) {
	struct br_infra_rxq_set_req req = {.cpu_id = 2, .port_id = 1, .rxq_id = 1};
	common_mocks();
	assert_api_out(rxq_set(&req, NULL), 0, 0);
}

static void rxq_set_existing_worker(void **) {
	struct br_infra_rxq_set_req req = {.cpu_id = 1, .port_id = 1, .rxq_id = 1};
	common_mocks();
	assert_api_out(rxq_set(&req, NULL), 0, 0);
	assert_int_equal(arrlen(w1.rxqs), 4);
	assert_int_equal(arrlen(w2.rxqs), 2);
}

static void rxq_set_existing_worker_destroy(void **) {
	struct br_infra_rxq_set_req req = {.cpu_id = 1, .port_id = 2, .rxq_id = 0};
	common_mocks();

	assert_api_out(rxq_set(&req, NULL), 0, 0);
	assert_int_equal(arrlen(w1.rxqs), 5);
	assert_int_equal(arrlen(w2.rxqs), 1);

	req.rxq_id = 1;
	will_return_count(port_reconfig, 0, 3);
	assert_api_out(rxq_set(&req, NULL), 0, 0);
	assert_int_equal(arrlen(w1.rxqs), 6);
	assert_int_equal(worker_count(), 1);
}

static void rxq_set_new_worker(void **) {
	struct br_infra_rxq_set_req req = {.cpu_id = 2, .port_id = 2, .rxq_id = 1};
	common_mocks();

	will_return_count(port_reconfig, 0, 3);
	will_return(__wrap_rte_zmalloc, &w2);
	will_return(__wrap_pthread_create, 0);
	assert_api_out(rxq_set(&req, NULL), 0, 0);
	assert_int_equal(arrlen(w1.rxqs), 5);
	assert_int_equal(arrlen(w2.rxqs), 1);
	assert_int_equal(worker_count(), 2);
}

static void rxq_set_new_worker_destroy(void **) {
	struct br_infra_rxq_set_req req = {.cpu_id = 3, .port_id = 2, .rxq_id = 1};
	common_mocks();

	will_return(__wrap_rte_zmalloc, &w3);
	will_return(__wrap_pthread_create, 0);
	assert_api_out(rxq_set(&req, NULL), 0, 0);
	assert_int_equal(arrlen(w1.rxqs), 5);
	assert_int_equal(arrlen(w3.rxqs), 1);
	assert_int_equal(worker_count(), 2);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(rxq_set_main_lcore),
		cmocka_unit_test(rxq_set_invalid_cpu),
		cmocka_unit_test(rxq_set_invalid_port),
		cmocka_unit_test(rxq_set_invalid_rxq),
		cmocka_unit_test(rxq_set_already_set),
		cmocka_unit_test(rxq_set_existing_worker),
		cmocka_unit_test(rxq_set_existing_worker_destroy),
		cmocka_unit_test(rxq_set_new_worker),
		cmocka_unit_test(rxq_set_new_worker_destroy),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
