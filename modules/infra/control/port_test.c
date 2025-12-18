// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "port_priv.h"
#include "worker_priv.h"

#include <gr_cmocka.h>
#include <gr_config.h>
#include <gr_event.h>
#include <gr_log.h>
#include <gr_mempool.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_rcu.h>
#include <gr_vrf.h>
#include <gr_worker.h>

// mocked types/functions
int gr_rte_log_type;
struct gr_config gr_config;
struct workers workers;
void gr_register_api_handler(struct gr_api_handler *) { }
void gr_register_module(struct gr_module *) { }
void iface_type_register(const struct iface_type *) { }
void gr_event_push(uint32_t, const void *) { }
void gr_event_subscribe(struct gr_event_subscription *) { }
mock_func(struct rte_mempool *, gr_pktmbuf_pool_get(int8_t, uint32_t));
void gr_pktmbuf_pool_release(struct rte_mempool *, uint32_t) { }
struct rte_rcu_qsbr *gr_datapath_rcu(void) {
	static struct rte_rcu_qsbr rcu;
	return &rcu;
}
uint16_t vrf_default_get_or_create(void) {
	return 0;
}
int vrf_incref(uint16_t) {
	return 0;
}
int iface_set_eth_addr(struct iface *, const struct rte_ether_addr *) {
	return 0;
}
mock_func(struct iface *, iface_from_id(uint16_t));
mock_func(struct iface *, iface_next(gr_iface_type_t, const struct iface *));
mock_func(int, port_unplug(struct iface_info_port *));
mock_func(int, port_plug(struct iface_info_port *));
mock_func(unsigned, worker_count(void));
mock_func(int, worker_queue_distribute(const cpu_set_t *, gr_vec struct iface_info_port **));
mock_func(int, __wrap_rte_eth_allmulticast_disable(uint16_t));
mock_func(int, __wrap_rte_eth_allmulticast_enable(uint16_t));
mock_func(int, __wrap_rte_eth_allmulticast_get(uint16_t));
mock_func(int, __wrap_rte_eth_dev_mac_addr_add(uint16_t, struct rte_ether_addr *, uint32_t));
mock_func(int, __wrap_rte_eth_dev_mac_addr_remove(uint16_t, struct rte_ether_addr *));
mock_func(int, __wrap_rte_eth_dev_set_mc_addr_list(uint16_t, struct rte_ether_addr *, uint32_t));
mock_func(int, __wrap_rte_eth_promiscuous_disable(uint16_t));
mock_func(int, __wrap_rte_eth_promiscuous_enable(uint16_t));
mock_func(int, __wrap_rte_eth_promiscuous_get(uint16_t));
void gr_metrics_ctx_init(struct gr_metrics_ctx *, struct gr_metrics_writer *, ...) { }
void gr_metrics_labels_add(struct gr_metrics_ctx *, ...) { }
void gr_metric_emit(struct gr_metrics_ctx *, const struct gr_metric *, uint64_t) { }

// test harness init
static const struct rte_ether_addr default_mac = {{0x02, 0xf0, 0x00, 0xb4, 0x47, 0x01}};
static struct iface *iface;

static int setup(void **) {
	struct iface_info_port *port;

	iface = calloc(1, sizeof(*iface) + sizeof(*port));
	assert_non_null(iface);
	iface->name = strdup("p0");
	iface->type = GR_IFACE_TYPE_PORT;
	iface->flags = GR_IFACE_F_UP;
	iface->state = GR_IFACE_S_RUNNING;
	port = iface_info_port(iface);
	port->started = true;
	port->port_id = 42;
	port->n_rxq = 1;
	port->n_txq = 2;
	port->mac = default_mac;

	return 0;
}

static int teardown(void **) {
	free(iface->name);
	free(iface);
	return 0;
}

static const struct rte_ether_addr ucast1 = {{0x2c, 0x4c, 0x15, 0x07, 0x99, 0x22}};
static const struct rte_ether_addr ucast2 = {{0x30, 0x3e, 0xa7, 0x0b, 0xea, 0x78}};
static const struct rte_ether_addr ucast3 = {{0xe6, 0x2c, 0xd9, 0xa5, 0xe7, 0x6e}};

static void mac_add_unicast(void **) {
	const struct iface_info_port *port = iface_info_port(iface);

	assert_int_equal(port_mac_add(iface, NULL), -EINVAL);
	assert_return_code(port_mac_add(iface, &default_mac), errno);
	assert_int_equal(port->filter.count, 0);

	will_return(__wrap_rte_eth_dev_mac_addr_add, 0);
	assert_return_code(port_mac_add(iface, &ucast1), errno);
	assert_int_equal(port->filter.count, 1);
	assert_int_equal(port->filter.macs[0].refcnt, 1);

	will_return(__wrap_rte_eth_dev_mac_addr_add, 0);
	assert_return_code(port_mac_add(iface, &ucast2), errno);
	assert_int_equal(port->filter.count, 2);
	assert_int_equal(port->filter.macs[1].refcnt, 1);

	assert_return_code(port_mac_add(iface, &ucast1), errno);
	assert_int_equal(port->filter.count, 2);
	assert_int_equal(port->filter.macs[0].refcnt, 2);

	will_return(__wrap_rte_eth_dev_mac_addr_add, -ENOSPC);
	will_return(__wrap_rte_eth_promiscuous_enable, 0);
	will_return(__wrap_rte_eth_dev_mac_addr_remove, 0);
	will_return(__wrap_rte_eth_dev_mac_addr_remove, 0);
	assert_return_code(port_mac_add(iface, &ucast3), errno);
	assert_true(port->filter.flags & MAC_FILTER_F_NOSPC);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(port->filter.count, 3);
	assert_int_equal(port->filter.hw_limit, 2);
}

static void mac_del_unicast(void **) {
	const struct iface_info_port *port = iface_info_port(iface);

	assert_return_code(port_promisc_set(iface, false), errno);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);

	assert_return_code(port_mac_del(iface, &ucast1), errno);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);

	will_return(__wrap_rte_eth_promiscuous_disable, 0);
	will_return(__wrap_rte_eth_dev_mac_addr_add, 0);
	will_return(__wrap_rte_eth_dev_mac_addr_add, 0);
	assert_return_code(port_mac_del(iface, &ucast1), errno);
	assert_false(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(port->filter.count, 2);
	assert_int_equal(port->filter.hw_limit, 0);
	assert_memory_equal(&port->filter.macs[0].mac, &ucast3, sizeof(ucast3));
	assert_memory_equal(&port->filter.macs[1].mac, &ucast2, sizeof(ucast2));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(mac_add_unicast),
		cmocka_unit_test(mac_del_unicast),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
