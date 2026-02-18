// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_cmocka.h>
#include <gr_event.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_vrf.h>

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
void fdb_purge_iface(uint16_t) { }
void fdb_purge_bridge(uint16_t) { }
// RSTP stubs needed by bridge.c.
#include "rstp_priv.h"
enum rstp_port_state rstp_get_port_state(const struct iface *bridge, uint16_t iface_id) {
	(void)bridge; (void)iface_id;
	return RSTP_STATE_FORWARDING;
}
void rstp_bridge_free(struct rstp_bridge *rstp) { (void)rstp; }
// VLAN filtering stubs needed by bridge.c.
#include "vlan_filtering_priv.h"
void vlan_filtering_free(struct vlan_filtering *vf) { (void)vf; }
// Multicast snooping stubs needed by bridge.c.
#include "mcast_snooping_priv.h"
void mcast_snooping_free(struct mcast_snooping *m) { (void)m; }
// LLDP stubs needed by bridge.c.
#include "lldp_priv.h"
void lldp_config_free(struct lldp_config *c) { (void)c; }
int iface_set_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	(void)iface;
	(void)mac;
	return 0;
}

// Test interface security defaults.
static void test_iface_security_defaults(void **state) {
	(void)state;

	// New interfaces should have no MAC limit and not be shutdown.
	assert_int_equal(iface_get_max_macs(0), 0);
	assert_false(iface_get_shutdown_on_violation(0));
	assert_false(iface_is_shutdown(0));
	assert_int_equal(iface_get_total_macs(0), 0);
}

// Test interface security bounds checking.
static void test_iface_security_bounds(void **state) {
	(void)state;

	// Out-of-bounds iface IDs should return safe defaults.
	assert_int_equal(iface_get_max_macs(L2_MAX_IFACES), 0);
	assert_int_equal(iface_get_max_macs(L2_MAX_IFACES + 1), 0);
	assert_false(iface_is_shutdown(L2_MAX_IFACES));
	assert_false(iface_get_shutdown_on_violation(L2_MAX_IFACES));
	assert_int_equal(iface_get_total_macs(L2_MAX_IFACES), 0);
}

// Test MAC limit configuration and enforcement.
static void test_iface_security_mac_limits(void **state) {
	(void)state;
	uint16_t iface_id = 42;

	// Clear state.
	memset(&l2_iface_security[iface_id], 0, sizeof(l2_iface_security[0]));
	memset(l2_iface_mac_counts[iface_id], 0, sizeof(l2_iface_mac_counts[0]));

	// Set a MAC limit.
	l2_iface_security[iface_id].max_macs = 5;
	assert_int_equal(iface_get_max_macs(iface_id), 5);

	// Increment MAC count on core 0.
	iface_increment_mac_count(iface_id, 0);
	iface_increment_mac_count(iface_id, 0);
	assert_int_equal(iface_get_total_macs(iface_id), 2);

	// Increment on a different core.
	iface_increment_mac_count(iface_id, 1);
	assert_int_equal(iface_get_total_macs(iface_id), 3);

	// Decrement.
	iface_decrement_mac_count(iface_id, 0);
	assert_int_equal(iface_get_total_macs(iface_id), 2);

	// Decrement below zero should clamp to 0.
	iface_decrement_mac_count(iface_id, 1);
	iface_decrement_mac_count(iface_id, 1);
	assert_int_equal(iface_get_total_macs(iface_id), 1);

	// Cleanup.
	memset(&l2_iface_security[iface_id], 0, sizeof(l2_iface_security[0]));
	memset(l2_iface_mac_counts[iface_id], 0, sizeof(l2_iface_mac_counts[0]));
}

// Test shutdown-on-violation behavior.
static void test_iface_security_shutdown(void **state) {
	(void)state;
	uint16_t iface_id = 10;

	// Clear state.
	memset(&l2_iface_security[iface_id], 0, sizeof(l2_iface_security[0]));

	// Enable shutdown-on-violation.
	l2_iface_security[iface_id].shutdown_on_violation = true;
	assert_true(iface_get_shutdown_on_violation(iface_id));
	assert_false(iface_is_shutdown(iface_id));

	// Trigger violation.
	iface_shutdown_violation(iface_id);
	assert_true(iface_is_shutdown(iface_id));

	// Cleanup.
	memset(&l2_iface_security[iface_id], 0, sizeof(l2_iface_security[0]));
}

// Test bridge stats accessor bounds.
static void test_bridge_stats_bounds(void **state) {
	(void)state;

	assert_non_null(bridge_get_stats(0, 0));
	assert_non_null(bridge_get_stats(L2_MAX_BRIDGES - 1, 0));
	assert_null(bridge_get_stats(L2_MAX_BRIDGES, 0));

	assert_non_null(fdb_get_stats(0, 0));
	assert_non_null(fdb_get_stats(L2_MAX_BRIDGES - 1, 0));
	assert_null(fdb_get_stats(L2_MAX_BRIDGES, 0));
}

// Test bridge stats increment.
static void test_bridge_stats_increment(void **state) {
	(void)state;
	uint16_t bridge_id = 5;

	memset(l2_bridge_stats[bridge_id], 0, sizeof(l2_bridge_stats[0]));

	struct bridge_stats *st = bridge_get_stats(bridge_id, 0);
	assert_non_null(st);
	assert_int_equal(st->unicast_fwd, 0);

	st->unicast_fwd++;
	st->learn_ok += 3;

	assert_int_equal(bridge_get_stats(bridge_id, 0)->unicast_fwd, 1);
	assert_int_equal(bridge_get_stats(bridge_id, 0)->learn_ok, 3);

	// Different core should have independent stats.
	struct bridge_stats *st2 = bridge_get_stats(bridge_id, 1);
	assert_int_equal(st2->unicast_fwd, 0);

	memset(l2_bridge_stats[bridge_id], 0, sizeof(l2_bridge_stats[0]));
}

// Test RSTP helper defaults (no RSTP configured).
static void test_rstp_defaults(void **state) {
	(void)state;

	// When bridge is NULL, helpers should allow forwarding/learning.
	assert_true(rstp_port_is_forwarding(NULL, 0));
	assert_true(rstp_port_is_learning(NULL, 0));
}

// Test feature accessor helpers with NULL bridge.
static void test_feature_accessors_null(void **state) {
	(void)state;

	assert_null(bridge_get_rstp(NULL));
	assert_null(bridge_get_mcast_snooping(NULL));
	assert_null(bridge_get_vlan_filtering(NULL));
	assert_null(bridge_get_lldp_config(NULL));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_iface_security_defaults),
		cmocka_unit_test(test_iface_security_bounds),
		cmocka_unit_test(test_iface_security_mac_limits),
		cmocka_unit_test(test_iface_security_shutdown),
		cmocka_unit_test(test_bridge_stats_bounds),
		cmocka_unit_test(test_bridge_stats_increment),
		cmocka_unit_test(test_rstp_defaults),
		cmocka_unit_test(test_feature_accessors_null),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
