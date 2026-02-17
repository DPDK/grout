// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include "gr_bond.h"

#include <gr_cmocka.h>
#include <gr_event.h>
#include <gr_log.h>
#include <gr_metrics.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_vrf.h>

#include <stdlib.h>
#include <string.h>

int gr_rte_log_type;

// Mocked functions required by the linker.
void gr_register_api_handler(struct gr_api_handler *) { }
void gr_register_module(struct gr_module *) { }
void iface_type_register(const struct iface_type *) { }
void gr_event_push(uint32_t, const void *) { }
void gr_event_subscribe(struct gr_event_subscription *) { }
uint16_t vrf_default_get_or_create(void) { return 0; }
int vrf_incref(uint16_t) { return 0; }
struct iface *iface_from_id(uint16_t) { return NULL; }
int iface_get_eth_addr(const struct iface *iface, struct rte_ether_addr *mac) {
	(void)iface;
	memset(mac, 0, sizeof(*mac));
	return 0;
}
int iface_set_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	(void)iface;
	(void)mac;
	return 0;
}
int port_set_vlan_offload(struct iface *iface, bool enable) {
	(void)iface;
	(void)enable;
	return 0;
}
int iface_set_mtu(struct iface *iface, uint16_t mtu) {
	(void)iface;
	(void)mtu;
	return 0;
}
int iface_add_eth_addr(struct iface *iface, const struct rte_ether_addr *addr) {
	(void)iface;
	(void)addr;
	return 0;
}
int iface_del_eth_addr(struct iface *iface, const struct rte_ether_addr *addr) {
	(void)iface;
	(void)addr;
	return 0;
}
int iface_set_promisc(struct iface *iface, bool enable) {
	(void)iface;
	(void)enable;
	return 0;
}
int port_unplug(struct iface_info_port *port) {
	(void)port;
	return 0;
}
int port_plug(struct iface_info_port *port) {
	(void)port;
	return 0;
}
struct iface *iface_next(gr_iface_type_t type, const struct iface *prev) {
	(void)type;
	(void)prev;
	return NULL;
}
void gr_metrics_ctx_init(struct gr_metrics_ctx *ctx, struct gr_metrics_writer *w, ...) {
	(void)ctx;
	(void)w;
}
void gr_metrics_labels_add(struct gr_metrics_ctx *ctx, ...) { (void)ctx; }
void gr_metric_emit(struct gr_metrics_ctx *ctx, const struct gr_metric *m, uint64_t v) {
	(void)ctx;
	(void)m;
	(void)v;
}

static struct iface *alloc_bond_iface(void) {
	struct iface *iface = calloc(1, sizeof(*iface) + sizeof(struct iface_info_bond));
	assert_non_null(iface);
	iface->type = GR_IFACE_TYPE_BOND;
	return iface;
}

static void test_bridge_member_set_clear(void **state) {
	(void)state;
	struct iface *iface = alloc_bond_iface();
	struct iface_info_bond *bond = iface_info_bond(iface);

	assert_false(bond->bridge_int.is_bridge_member);
	assert_int_equal(bond->bridge_int.bridge_id, 0);

	bond_set_bridge_member(iface, 7);
	assert_true(bond->bridge_int.is_bridge_member);
	assert_int_equal(bond->bridge_int.bridge_id, 7);

	bond_clear_bridge_member(iface);
	assert_false(bond->bridge_int.is_bridge_member);
	assert_int_equal(bond->bridge_int.bridge_id, 0);

	free(iface);
}

static void test_active_member_count(void **state) {
	(void)state;
	struct iface *iface = alloc_bond_iface();
	struct iface_info_bond *bond = iface_info_bond(iface);

	assert_int_equal(bond_get_active_member_count(iface), 0);

	bond->bridge_int.n_active_members = 3;
	assert_int_equal(bond_get_active_member_count(iface), 3);

	bond->bridge_int.n_active_members = 0;
	assert_int_equal(bond_get_active_member_count(iface), 0);

	free(iface);
}

static void test_operationally_up_no_bridge(void **state) {
	(void)state;
	struct iface *iface = alloc_bond_iface();

	// Not a bridge member: follows GR_IFACE_S_RUNNING flag.
	iface->state = GR_IFACE_S_RUNNING;
	assert_true(bond_is_operationally_up(iface));

	iface->state = 0;
	assert_false(bond_is_operationally_up(iface));

	free(iface);
}

static void test_operationally_up_no_min_links(void **state) {
	(void)state;
	struct iface *iface = alloc_bond_iface();
	struct iface_info_bond *bond = iface_info_bond(iface);

	// Bridge member with min_active_links=0: follows RUNNING flag.
	bond->bridge_int.is_bridge_member = true;
	bond->bridge_int.min_active_links = 0;

	iface->state = GR_IFACE_S_RUNNING;
	assert_true(bond_is_operationally_up(iface));

	iface->state = 0;
	assert_false(bond_is_operationally_up(iface));

	free(iface);
}

static void test_operationally_up_min_links(void **state) {
	(void)state;
	struct iface *iface = alloc_bond_iface();
	struct iface_info_bond *bond = iface_info_bond(iface);

	bond->bridge_int.is_bridge_member = true;
	bond->bridge_int.min_active_links = 2;

	// Below threshold.
	bond->bridge_int.n_active_members = 1;
	assert_false(bond_is_operationally_up(iface));

	// At threshold.
	bond->bridge_int.n_active_members = 2;
	assert_true(bond_is_operationally_up(iface));

	// Above threshold.
	bond->bridge_int.n_active_members = 4;
	assert_true(bond_is_operationally_up(iface));

	free(iface);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_bridge_member_set_clear),
		cmocka_unit_test(test_active_member_count),
		cmocka_unit_test(test_operationally_up_no_bridge),
		cmocka_unit_test(test_operationally_up_no_min_links),
		cmocka_unit_test(test_operationally_up_min_links),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
