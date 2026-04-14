// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "_cmocka.h"
#include "config.h"
#include "event.h"
#include "iface.h"
#include "log.h"
#include "mempool.h"
#include "module.h"
#include "netlink.h"
#include "port.h"
#include "rcu.h"
#include "vlan.h"
#include "vrf.h"
#include "worker.h"

// mocked types/functions
int gr_rte_log_type;
struct log_types log_types = STAILQ_HEAD_INITIALIZER(log_types);
struct gr_config gr_config;
struct workers workers;
void module_register(struct module *) { }
void event_push(uint32_t, const void *) { }
void event_subscribe(uint32_t, event_sub_cb_t) { }
int netlink_link_set_name(uint32_t, const char *) {
	return 0;
}
int netlink_set_ifalias(uint32_t, const char *) {
	return 0;
}
mock_func(struct rte_mempool *, gr_pktmbuf_pool_get(int8_t, uint32_t));
void gr_pktmbuf_pool_release(struct rte_mempool *, uint32_t) { }
struct rte_rcu_qsbr *gr_datapath_rcu(void) {
	static struct rte_rcu_qsbr rcu;
	return &rcu;
}
int vrf_incref(uint16_t) {
	return 0;
}
void vrf_decref(uint16_t) { }
bool vrf_has_interfaces(uint16_t) {
	return false;
}
void control_queue_drain(uint32_t, const void *) { }
mock_func(struct iface *, __wrap_iface_from_id(uint16_t));
mock_func(int, port_unplug(struct iface_info_port *));
mock_func(int, port_plug(struct iface_info_port *));
mock_func(unsigned, worker_count(void));
mock_func(int, worker_queue_distribute(const cpu_set_t *, vec struct iface_info_port **));
mock_func(int, __wrap_rte_eth_allmulticast_enable(uint16_t));
mock_func(int, __wrap_rte_eth_dev_mac_addr_add(uint16_t, struct rte_ether_addr *, uint32_t));
mock_func(int, __wrap_rte_eth_dev_mac_addr_remove(uint16_t, struct rte_ether_addr *));
mock_func(int, __wrap_rte_eth_promiscuous_disable(uint16_t));
mock_func(int, __wrap_rte_eth_promiscuous_enable(uint16_t));
mock_func(int, __wrap_rte_eth_promiscuous_get(uint16_t));
void metrics_ctx_init(struct metrics_ctx *, struct metrics_writer *, ...) { }
void metrics_labels_add(struct metrics_ctx *, ...) { }
void metric_emit(struct metrics_ctx *, const struct metric *, uint64_t) { }

// test harness init
static const struct rte_ether_addr default_mac = {{0x02, 0xf0, 0x00, 0xb4, 0x47, 0x01}};
static struct iface *iface;
static const struct rte_ether_addr default_vlan_mac = {{0x02, 0xff, 0x00, 0xb4, 0x47, 0x01}};
static struct iface *vlan_iface;

static int setup(void **) {
	struct iface_info_port *port;
	struct iface_info_vlan *vlan;

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

	vlan_iface = calloc(1, sizeof(*vlan_iface) + sizeof(*vlan));
	assert_non_null(vlan_iface);
	vlan_iface->name = strdup("p0.23");
	vlan_iface->type = GR_IFACE_TYPE_VLAN;
	vlan_iface->flags = GR_IFACE_F_UP;
	vlan_iface->state = GR_IFACE_S_RUNNING;
	vlan = iface_info_vlan(vlan_iface);
	vlan->parent_id = 42;
	vlan->vlan_id = 23;
	vlan->mac = default_vlan_mac;

	return 0;
}

static int teardown(void **) {
	free(iface->name);
	vec_free(iface->macs);
	free(iface);
	free(vlan_iface->name);
	vec_free(vlan_iface->macs);
	free(vlan_iface);
	return 0;
}

static const struct rte_ether_addr mcast1 = {{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}};
static const struct rte_ether_addr ucast1 = {{0x2c, 0x4c, 0x15, 0x07, 0x99, 0x22}};
static const struct rte_ether_addr ucast2 = {{0x30, 0x3e, 0xa7, 0x0b, 0xea, 0x78}};
static const struct rte_ether_addr ucast3 = {{0xe6, 0x2c, 0xd9, 0xa5, 0xe7, 0x6e}};

static void port_mac_add_multicast(void **) {
	assert_return_code(iface_add_eth_addr(iface, &mcast1), errno);
	assert_int_equal(vec_len(iface->macs), 0);
}

static void port_mac_add_unicast(void **) {
	assert_int_equal(iface_add_eth_addr(iface, NULL), -EINVAL);

	assert_return_code(iface_add_eth_addr(iface, &default_mac), errno);
	assert_int_equal(vec_len(iface->macs), 0);

	will_return(__wrap_rte_eth_dev_mac_addr_add, 0);
	assert_return_code(iface_add_eth_addr(iface, &ucast1), errno);
	assert_false(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(vec_len(iface->macs), 1);
	assert_memory_equal(&iface->macs[0].mac, &ucast1, sizeof(ucast1));
	assert_int_equal(iface->macs[0].refcnt, 1);
	assert_true(iface->macs[0].hardware);

	will_return(__wrap_rte_eth_dev_mac_addr_add, 0);
	assert_return_code(iface_add_eth_addr(iface, &ucast2), errno);
	assert_false(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(vec_len(iface->macs), 2);
	assert_memory_equal(&iface->macs[1].mac, &ucast2, sizeof(ucast2));
	assert_int_equal(iface->macs[1].refcnt, 1);
	assert_true(iface->macs[1].hardware);

	assert_return_code(iface_add_eth_addr(iface, &ucast1), errno);
	assert_int_equal(vec_len(iface->macs), 2);
	assert_memory_equal(&iface->macs[0].mac, &ucast1, sizeof(ucast1));
	assert_int_equal(iface->macs[0].refcnt, 2);
	assert_true(iface->macs[0].hardware);

	will_return(__wrap_rte_eth_dev_mac_addr_add, -ENOSPC);
	will_return(__wrap_rte_eth_promiscuous_enable, 0);
	assert_return_code(iface_add_eth_addr(iface, &ucast3), errno);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(vec_len(iface->macs), 3);
	assert_memory_equal(&iface->macs[2].mac, &ucast3, sizeof(ucast3));
	assert_int_equal(iface->macs[2].refcnt, 1);
	assert_false(iface->macs[2].hardware);
}

static void port_mac_del_unicast(void **) {
	assert_return_code(iface_set_promisc(iface, false), errno);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);

	assert_return_code(iface_del_eth_addr(iface, &ucast1), errno);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_memory_equal(&iface->macs[0].mac, &ucast1, sizeof(ucast1));
	assert_int_equal(iface->macs[0].refcnt, 1);
	assert_true(iface->macs[0].hardware);

	will_return(__wrap_rte_eth_dev_mac_addr_remove, 0);
	will_return(__wrap_rte_eth_dev_mac_addr_add, 0);
	will_return(__wrap_rte_eth_promiscuous_disable, 0);
	assert_return_code(iface_del_eth_addr(iface, &ucast1), errno);
	assert_false(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(vec_len(iface->macs), 2);
	assert_memory_equal(&iface->macs[0].mac, &ucast2, sizeof(ucast2));
	assert_int_equal(iface->macs[0].refcnt, 1);
	assert_true(iface->macs[0].hardware);
	assert_memory_equal(&iface->macs[1].mac, &ucast3, sizeof(ucast3));
	assert_int_equal(iface->macs[1].refcnt, 1);
	assert_true(iface->macs[1].hardware);
}

static void vlan_mac_add_multicast(void **) {
	assert_return_code(iface_add_eth_addr(vlan_iface, &mcast1), errno);
	assert_int_equal(vec_len(vlan_iface->macs), 0);
}

static void vlan_mac_add_unicast(void **) {
	assert_int_equal(iface_add_eth_addr(vlan_iface, NULL), -EINVAL);

	assert_return_code(iface_add_eth_addr(vlan_iface, &default_vlan_mac), errno);
	assert_int_equal(vec_len(vlan_iface->macs), 0);

	// the underlying port iface still knows ucast2 and ucast3
	will_return(__wrap_rte_eth_dev_mac_addr_add, -ENOSPC);
	will_return(__wrap_rte_eth_promiscuous_enable, 0);
	will_return(__wrap_iface_from_id, iface);
	assert_return_code(iface_add_eth_addr(vlan_iface, &ucast1), errno);
	assert_int_equal(vec_len(vlan_iface->macs), 1);
	assert_memory_equal(&vlan_iface->macs[0].mac, &ucast1, sizeof(ucast1));
	assert_int_equal(vlan_iface->macs[0].refcnt, 1);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(vec_len(iface->macs), 3);
	assert_memory_equal(&iface->macs[2].mac, &ucast1, sizeof(ucast1));
	assert_int_equal(iface->macs[2].refcnt, 1);
	assert_false(iface->macs[2].hardware);

	will_return(__wrap_iface_from_id, iface);
	assert_return_code(iface_add_eth_addr(vlan_iface, &ucast2), errno);
	assert_int_equal(vec_len(vlan_iface->macs), 2);
	assert_memory_equal(&vlan_iface->macs[1].mac, &ucast2, sizeof(ucast2));
	assert_int_equal(vlan_iface->macs[1].refcnt, 1);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(vec_len(iface->macs), 3);
	assert_memory_equal(&iface->macs[0].mac, &ucast2, sizeof(ucast2));
	assert_int_equal(iface->macs[0].refcnt, 2);
	assert_true(iface->macs[0].hardware);

	assert_return_code(iface_add_eth_addr(vlan_iface, &ucast1), errno);
	assert_int_equal(vec_len(vlan_iface->macs), 2);
	assert_memory_equal(&vlan_iface->macs[0].mac, &ucast1, sizeof(ucast1));
	assert_int_equal(vlan_iface->macs[0].refcnt, 2);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(vec_len(iface->macs), 3);
	assert_memory_equal(&iface->macs[2].mac, &ucast1, sizeof(ucast1));
	assert_int_equal(iface->macs[2].refcnt, 1);
	assert_false(iface->macs[2].hardware);

	will_return(__wrap_iface_from_id, iface);
	assert_return_code(iface_add_eth_addr(vlan_iface, &ucast3), errno);
	assert_int_equal(vec_len(vlan_iface->macs), 3);
	assert_memory_equal(&vlan_iface->macs[2].mac, &ucast3, sizeof(ucast3));
	assert_int_equal(vlan_iface->macs[2].refcnt, 1);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(vec_len(iface->macs), 3);
	assert_memory_equal(&iface->macs[1].mac, &ucast3, sizeof(ucast3));
	assert_int_equal(iface->macs[1].refcnt, 2);
	assert_true(iface->macs[1].hardware);
}

static void vlan_mac_del_unicast(void **) {
	assert_return_code(iface_del_eth_addr(vlan_iface, &ucast1), errno);
	assert_memory_equal(&vlan_iface->macs[0].mac, &ucast1, sizeof(ucast1));
	assert_int_equal(vlan_iface->macs[0].refcnt, 1);
	assert_true(iface->state & GR_IFACE_S_PROMISC_FIXED);
	assert_int_equal(vec_len(iface->macs), 3);
	assert_memory_equal(&iface->macs[2].mac, &ucast1, sizeof(ucast1));
	assert_int_equal(iface->macs[2].refcnt, 1);
	assert_false(iface->macs[2].hardware);

	will_return(__wrap_iface_from_id, iface);
	will_return(__wrap_rte_eth_promiscuous_disable, 0);
	assert_return_code(iface_del_eth_addr(vlan_iface, &ucast1), errno);
	assert_int_equal(vec_len(vlan_iface->macs), 2);
	assert_memory_equal(&vlan_iface->macs[0].mac, &ucast2, sizeof(ucast2));
	assert_int_equal(vlan_iface->macs[0].refcnt, 1);
	assert_memory_equal(&vlan_iface->macs[1].mac, &ucast3, sizeof(ucast3));
	assert_int_equal(vlan_iface->macs[1].refcnt, 1);
	assert_int_equal(vec_len(iface->macs), 2);
	assert_memory_equal(&iface->macs[0].mac, &ucast2, sizeof(ucast2));
	assert_int_equal(iface->macs[0].refcnt, 2);
	assert_memory_equal(&iface->macs[1].mac, &ucast3, sizeof(ucast3));
	assert_int_equal(iface->macs[1].refcnt, 2);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(port_mac_add_multicast),
		cmocka_unit_test(port_mac_add_unicast),
		cmocka_unit_test(port_mac_del_unicast),
		cmocka_unit_test(vlan_mac_add_multicast),
		cmocka_unit_test(vlan_mac_add_unicast),
		cmocka_unit_test(vlan_mac_del_unicast),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
