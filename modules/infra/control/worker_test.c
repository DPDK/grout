// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "worker_priv.h"

#include <gr_api.h>
#include <gr_cmocka.h>
#include <gr_config.h>
#include <gr_event.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_mempool.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_queue.h>
#include <gr_vec.h>
#include <gr_worker.h>

#include <numa.h>
#include <rte_ethdev.h>

static struct iface *ifaces[] = {NULL, NULL, NULL};
static struct worker w1 = {.cpu_id = 1};
static struct worker w2 = {.cpu_id = 2};
static struct worker w3 = {.cpu_id = 3};
static struct worker w4 = {.cpu_id = 4};
static struct worker w5 = {.cpu_id = 5};
static struct rte_eth_dev_info dev_info = {.driver_name = "net_null", .nb_rx_queues = 2};

// mocked types/functions
int gr_rte_log_type;
struct gr_config gr_config;
void gr_register_api_handler(struct gr_api_handler *) { }
void gr_register_module(struct gr_module *) { }
void iface_type_register(struct iface_type *) { }
void gr_event_push(uint32_t, const void *) { }
mock_func(struct rte_mempool *, gr_pktmbuf_pool_get(int8_t, uint32_t));
void gr_pktmbuf_pool_release(struct rte_mempool *, uint32_t) { }

struct iface *iface_from_id(uint16_t ifid) {
	return ifid < ARRAY_DIM(ifaces) ? ifaces[ifid] : NULL;
}

struct iface *iface_next(gr_iface_type_t /*type_id*/, const struct iface *prev) {
	uint16_t ifid;
	if (prev == NULL)
		ifid = 0;
	else
		ifid = prev->id + 1;
	if (ifid < ARRAY_DIM(ifaces))
		return ifaces[ifid];
	return NULL;
}

mock_func(int, worker_graph_reload(struct worker *, gr_vec struct iface_info_port **));
mock_func(int, worker_graph_reload_all(gr_vec struct iface_info_port **));
mock_func(void, worker_graph_free(struct worker *));
mock_func(void *, gr_datapath_loop(void *));
mock_func(void, __wrap_rte_free(void *));
mock_func(int, __wrap_rte_eth_dev_stop(uint16_t));
mock_func(
	struct rte_mempool *,
	__wrap_rte_pktmbuf_pool_create(
		const char *,
		unsigned int,
		unsigned int,
		uint16_t,
		uint16_t,
		int
	)
);
mock_func(void, __wrap_rte_mempool_free(struct rte_mempool *));
mock_func(
	int, __wrap_rte_eth_dev_info_get(uint16_t, struct rte_eth_dev_info *info), *info = dev_info;
);
mock_func(int, __wrap_rte_eth_dev_get_mtu(uint16_t, uint16_t *));
mock_func(int, __wrap_rte_eth_macaddr_get(uint16_t, struct rte_ether_addr *));
mock_func(
	int,
	__wrap_rte_eth_rx_queue_setup(
		uint16_t,
		uint16_t,
		uint16_t,
		unsigned int,
		const struct rte_eth_rxconf *,
		struct rte_mempool * /*pool*/
	)
);
mock_func(
	int,
	__wrap_rte_eth_tx_queue_setup(
		uint16_t,
		uint16_t,
		uint16_t,
		unsigned int,
		const struct rte_eth_txconf * /*conf*/
	)
);
mock_func(int, __wrap_numa_available(int));
mock_func(int, __wrap_numa_node_of_cpu(int));
mock_func(int, __wrap_rte_eth_dev_socket_id(uint16_t));
mock_func(int, __wrap_rte_eth_dev_start(uint16_t));
mock_func(const char *, __wrap_rte_dev_name(struct rte_device *));
mock_func(
	int,
	__wrap_rte_eth_dev_configure(uint16_t, uint16_t, uint16_t, const struct rte_eth_conf *)
);
mock_func(int, __wrap_pthread_cancel(pthread_t));
mock_func(int, __wrap_pthread_create(pthread_t *, const pthread_attr_t *, void *(void *), void *));
mock_func(int, __wrap_pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *));
mock_func(
	int,
	__wrap_pthread_cond_timedwait(pthread_cond_t *, pthread_mutex_t *, struct timespec *)
);
mock_func(int, __wrap_pthread_join(pthread_t *, const pthread_attr_t *, void *(void *), void *));
mock_func(void *, __wrap_rte_zmalloc(char *, size_t, unsigned));

#define assert_qmaps(qmaps, ...)                                                                   \
	do {                                                                                       \
		struct queue_map __expected[] = {__VA_ARGS__};                                     \
		uint32_t __len = sizeof(__expected) / sizeof(struct queue_map);                    \
		if (gr_vec_len(qmaps) != __len)                                                    \
			fail_msg("%s len %u expected %u", #qmaps, gr_vec_len(qmaps), __len);       \
		for (uint32_t __i = 0; __i < __len; __i++) {                                       \
			struct queue_map *exp = &__expected[__i], *act;                            \
			bool found = false;                                                        \
			gr_vec_foreach_ref (act, qmaps) {                                          \
				if (act->port_id != exp->port_id)                                  \
					continue;                                                  \
				if (act->queue_id != exp->queue_id)                                \
					continue;                                                  \
				found = true;                                                      \
				break;                                                             \
			}                                                                          \
			if (!found)                                                                \
				fail_msg(                                                          \
					"%s port %u queue %u not found",                           \
					#qmaps,                                                    \
					exp->port_id,                                              \
					exp->queue_id                                              \
				);                                                                 \
		}                                                                                  \
	} while (0)

static struct queue_map q(uint16_t port_id, uint16_t rxq_id) {
	struct queue_map qmap = {
		.port_id = port_id,
		.queue_id = rxq_id,
		.enabled = true,
	};
	return qmap;
}

static int setup(void **) {
	for (int i = 0; i < 3; i++) {
		struct iface_info_port *port;
		struct iface *iface = calloc(1, sizeof(*iface) + sizeof(*port));
		assert_non_null(iface);
		iface->id = i;
		iface->type = GR_IFACE_TYPE_PORT;
		port = iface_info_port(iface);
		port->started = true;
		port->port_id = i;
		port->n_rxq = 2;
		ifaces[i] = iface;
	}
	STAILQ_INSERT_TAIL(&workers, &w1, next);
	gr_vec_add(w1.rxqs, q(0, 0));
	gr_vec_add(w1.rxqs, q(0, 1));
	gr_vec_add(w1.rxqs, q(1, 0));

	gr_vec_add(w1.txqs, q(0, 0));
	gr_vec_add(w1.txqs, q(1, 0));
	gr_vec_add(w1.txqs, q(2, 0));

	STAILQ_INSERT_TAIL(&workers, &w2, next);
	gr_vec_add(w2.rxqs, q(1, 1));
	gr_vec_add(w2.rxqs, q(2, 0));
	gr_vec_add(w2.rxqs, q(2, 1));

	gr_vec_add(w2.txqs, q(0, 1));
	gr_vec_add(w2.txqs, q(1, 1));
	gr_vec_add(w2.txqs, q(2, 1));

	STAILQ_INSERT_TAIL(&workers, &w3, next);
	gr_vec_add(w3.txqs, q(0, 2));
	gr_vec_add(w3.txqs, q(1, 2));
	gr_vec_add(w3.txqs, q(2, 2));

	return 0;
}

static int teardown(void **) {
	struct worker *w;
	STAILQ_FOREACH (w, &workers, next) {
		gr_vec_free(w->rxqs);
		gr_vec_free(w->txqs);
	}
	STAILQ_INIT(&workers);
	for (int i = 0; i < 3; i++)
		free(ifaces[i]);
	return 0;
}

static void common_mocks(void) {
	will_return_maybe(worker_graph_free, 0);
	will_return_maybe(worker_graph_reload, 0);
	will_return_maybe(worker_graph_reload_all, 0);
	will_return_maybe(__wrap_numa_available, 0);
	will_return_maybe(__wrap_numa_node_of_cpu, 0);
	will_return_maybe(__wrap_pthread_cond_wait, 0);
	will_return_maybe(__wrap_pthread_cond_timedwait, 0);
	will_return_maybe(__wrap_pthread_create, 0);
	will_return_maybe(__wrap_pthread_join, 0);
	will_return_maybe(__wrap_rte_dev_name, "");
	will_return_maybe(__wrap_rte_eth_dev_configure, 0);
	will_return_maybe(__wrap_rte_eth_dev_get_mtu, 0);
	will_return_maybe(__wrap_rte_eth_dev_info_get, 0);
	will_return_maybe(__wrap_rte_eth_dev_socket_id, 0);
	will_return_maybe(__wrap_rte_eth_dev_start, 0);
	will_return_maybe(__wrap_rte_eth_dev_stop, 0);
	will_return_maybe(__wrap_rte_eth_macaddr_get, 0);
	will_return_maybe(__wrap_rte_eth_rx_queue_setup, 0);
	will_return_maybe(__wrap_rte_eth_tx_queue_setup, 0);
	will_return_maybe(__wrap_rte_free, 0);
	will_return_maybe(__wrap_rte_mempool_free, 0);
	will_return_maybe(__wrap_rte_pktmbuf_pool_create, 1);
	will_return_maybe(gr_pktmbuf_pool_get, 1);
	CPU_ZERO(&gr_config.control_cpus);
	CPU_SET(0, &gr_config.control_cpus);
	CPU_ZERO(&gr_config.datapath_cpus);
	CPU_SET(1, &gr_config.datapath_cpus);
	CPU_SET(2, &gr_config.datapath_cpus);
	CPU_SET(3, &gr_config.datapath_cpus);
}

static void rxq_assign_main_lcore(void **) {
	CPU_ZERO(&gr_config.control_cpus);
	CPU_SET(4, &gr_config.control_cpus);
	assert_int_equal(worker_rxq_assign(0, 0, 4), -EBUSY);
}

static void rxq_assign_invalid_cpu(void **) {
	CPU_ZERO(&gr_config.control_cpus);
	CPU_SET(0, &gr_config.control_cpus);
	assert_int_equal(worker_rxq_assign(0, 0, 9999), -ERANGE);
}

static void rxq_assign_invalid_port(void **) {
	common_mocks();
	assert_int_equal(worker_rxq_assign(9999, 0, 1), -ENODEV);
}

static void rxq_assign_invalid_rxq(void **) {
	common_mocks();
	assert_int_equal(worker_rxq_assign(0, 9999, 1), -ENODEV);
}

static void rxq_assign_already_set(void **) {
	common_mocks();
	assert_int_equal(worker_rxq_assign(1, 1, 2), 0);
}

static void rxq_assign_existing_worker(void **) {
	common_mocks();
	assert_int_equal(worker_rxq_assign(1, 1, 1), 0);
	assert_int_equal(worker_count(), 3);
	assert_qmaps(w1.rxqs, q(0, 0), q(0, 1), q(1, 0), q(1, 1));
	assert_qmaps(w2.rxqs, q(2, 1), q(2, 0));
	assert_qmaps(w3.rxqs);
	assert_qmaps(w1.txqs, q(0, 0), q(1, 0), q(2, 0));
	assert_qmaps(w2.txqs, q(0, 1), q(1, 1), q(2, 1));
	assert_qmaps(w3.txqs, q(0, 2), q(1, 2), q(2, 2));
}

static void rxq_assign_existing_worker_destroy(void **) {
	common_mocks();

	assert_int_equal(worker_rxq_assign(2, 0, 1), 0);
	assert_int_equal(worker_count(), 3);
	assert_qmaps(w1.rxqs, q(0, 0), q(0, 1), q(1, 0), q(1, 1), q(2, 0));
	assert_qmaps(w2.rxqs, q(2, 1));
	assert_qmaps(w3.rxqs);
	assert_qmaps(w1.txqs, q(0, 0), q(1, 0), q(2, 0));
	assert_qmaps(w2.txqs, q(0, 1), q(1, 1), q(2, 1));
	assert_qmaps(w3.txqs, q(0, 2), q(1, 2), q(2, 2));

	assert_int_equal(worker_rxq_assign(2, 1, 1), 0);
	assert_int_equal(worker_count(), 3);
	assert_qmaps(w1.rxqs, q(0, 0), q(0, 1), q(1, 0), q(1, 1), q(2, 0), q(2, 1));
	assert_qmaps(w2.rxqs);
	assert_qmaps(w3.rxqs);
	assert_qmaps(w1.txqs, q(1, 0), q(2, 0), q(0, 0));
	assert_qmaps(w2.txqs, q(0, 1), q(1, 1), q(2, 1));
	assert_qmaps(w3.txqs, q(0, 2), q(1, 2), q(2, 2));
}

static void rxq_assign_new_worker(void **) {
	common_mocks();

	assert_int_equal(worker_rxq_assign(2, 1, 2), 0);
	assert_int_equal(worker_count(), 3);
	assert_qmaps(w1.rxqs, q(0, 0), q(0, 1), q(1, 0), q(1, 1), q(2, 0));
	assert_qmaps(w2.rxqs, q(2, 1));
	assert_qmaps(w3.rxqs);
	assert_qmaps(w1.txqs, q(0, 0), q(1, 0), q(2, 0));
	assert_qmaps(w2.txqs, q(0, 1), q(1, 1), q(2, 1));
	assert_qmaps(w3.txqs, q(0, 2), q(1, 2), q(2, 2));
}

static void rxq_assign_new_worker_destroy(void **) {
	common_mocks();

	assert_int_equal(worker_rxq_assign(2, 1, 3), 0);
	assert_int_equal(worker_count(), 3);
	assert_qmaps(w1.rxqs, q(0, 0), q(0, 1), q(1, 0), q(1, 1), q(2, 0));
	assert_qmaps(w2.rxqs);
	assert_qmaps(w3.rxqs, q(2, 1));
	assert_qmaps(w1.txqs, q(0, 0), q(1, 0), q(2, 0));
	assert_qmaps(w2.txqs, q(0, 1), q(1, 1), q(2, 1));
	assert_qmaps(w3.txqs, q(0, 2), q(1, 2), q(2, 2));
}

static void rxq_assign_new_worker2(void **) {
	common_mocks();

	assert_int_equal(worker_rxq_assign(2, 0, 2), 0);
	assert_int_equal(worker_count(), 3);
	assert_qmaps(w1.rxqs, q(0, 0), q(0, 1), q(1, 0), q(1, 1));
	assert_qmaps(w2.rxqs, q(2, 0));
	assert_qmaps(w3.rxqs, q(2, 1));
	assert_qmaps(w1.txqs, q(0, 0), q(1, 0), q(2, 0));
	assert_qmaps(w2.txqs, q(0, 1), q(1, 1), q(2, 1));
	assert_qmaps(w3.txqs, q(0, 2), q(1, 2), q(2, 2));
}

static void queue_distribute_reduce(void **) {
	common_mocks();

	cpu_set_t affinity;
	CPU_ZERO(&affinity);
	CPU_SET(4, &affinity);
	CPU_SET(5, &affinity);
	gr_vec struct iface_info_port **ports = NULL;
	for (unsigned i = 0; i < ARRAY_DIM(ifaces); i++)
		gr_vec_add(ports, iface_info_port(ifaces[i]));

	will_return(__wrap_rte_zmalloc, &w4);
	will_return(__wrap_rte_zmalloc, &w5);
	assert_int_equal(worker_queue_distribute(&affinity, ports), 0);
	gr_vec_free(ports);
	assert_int_equal(worker_count(), 2);

	assert_qmaps(w1.rxqs);
	assert_qmaps(w2.rxqs);
	assert_qmaps(w3.rxqs);
	assert_qmaps(w4.rxqs, q(0, 0), q(1, 0), q(2, 0));
	assert_qmaps(w5.rxqs, q(0, 1), q(1, 1), q(2, 1));
	assert_qmaps(w1.txqs);
	assert_qmaps(w2.txqs);
	assert_qmaps(w3.txqs);
	assert_qmaps(w4.txqs, q(0, 0), q(1, 0), q(2, 0));
	assert_qmaps(w5.txqs, q(0, 1), q(1, 1), q(2, 1));

	for (unsigned i = 0; i < ARRAY_DIM(ifaces); i++) {
		struct iface_info_port *p = iface_info_port(ifaces[i]);
		assert_int_equal(p->n_txq, CPU_COUNT(&affinity));
	}
}

static void queue_distribute_increase(void **) {
	common_mocks();

	cpu_set_t affinity;
	CPU_ZERO(&affinity);
	CPU_SET(1, &affinity);
	CPU_SET(2, &affinity);
	CPU_SET(3, &affinity);
	CPU_SET(4, &affinity);
	CPU_SET(5, &affinity);
	gr_vec struct iface_info_port **ports = NULL;
	for (unsigned i = 0; i < ARRAY_DIM(ifaces); i++)
		gr_vec_add(ports, iface_info_port(ifaces[i]));

	will_return(__wrap_rte_zmalloc, &w1);
	will_return(__wrap_rte_zmalloc, &w2);
	will_return(__wrap_rte_zmalloc, &w3);
	assert_int_equal(worker_queue_distribute(&affinity, ports), 0);
	gr_vec_free(ports);
	assert_int_equal(worker_count(), 5);

	assert_qmaps(w1.rxqs, q(0, 0), q(2, 1));
	assert_qmaps(w2.rxqs, q(0, 1));
	assert_qmaps(w3.rxqs, q(1, 0));
	assert_qmaps(w4.rxqs, q(1, 1));
	assert_qmaps(w5.rxqs, q(2, 0));
	assert_qmaps(w1.txqs, q(0, 0), q(1, 0), q(2, 0));
	assert_qmaps(w2.txqs, q(0, 1), q(1, 1), q(2, 1));
	assert_qmaps(w3.txqs, q(0, 2), q(1, 2), q(2, 2));
	assert_qmaps(w4.txqs, q(0, 3), q(1, 3), q(2, 3));
	assert_qmaps(w5.txqs, q(0, 4), q(1, 4), q(2, 4));

	for (unsigned i = 0; i < ARRAY_DIM(ifaces); i++) {
		struct iface_info_port *p = iface_info_port(ifaces[i]);
		assert_int_equal(p->n_txq, CPU_COUNT(&affinity));
	}
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(rxq_assign_main_lcore),
		cmocka_unit_test(rxq_assign_invalid_cpu),
		cmocka_unit_test(rxq_assign_invalid_port),
		cmocka_unit_test(rxq_assign_invalid_rxq),
		cmocka_unit_test(rxq_assign_already_set),
		cmocka_unit_test(rxq_assign_existing_worker),
		cmocka_unit_test(rxq_assign_existing_worker_destroy),
		cmocka_unit_test(rxq_assign_new_worker),
		cmocka_unit_test(rxq_assign_new_worker_destroy),
		cmocka_unit_test(rxq_assign_new_worker2),
		cmocka_unit_test(queue_distribute_reduce),
		cmocka_unit_test(queue_distribute_increase),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
