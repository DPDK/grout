// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include "storm_control_priv.h"

#include <gr_cmocka.h>
#include <gr_log.h>

#include <rte_meter.h>

#include <stdlib.h>
#include <string.h>

int gr_rte_log_type;

// Mocked functions.
void gr_register_api_handler(struct gr_api_handler *) { }
struct iface *iface_from_id(uint16_t) { return NULL; }

uint64_t __wrap_rte_rdtsc(void) {
	return mock_type(uint64_t);
}

// Call real DPDK meter functions through wraps.
extern int __real_rte_meter_trtcm_profile_config(
	struct rte_meter_trtcm_profile *, const struct rte_meter_trtcm_params *
);
extern int __real_rte_meter_trtcm_config(
	struct rte_meter_trtcm *, const struct rte_meter_trtcm_profile *
);

int __wrap_rte_meter_trtcm_profile_config(void *profile, void *params) {
	return __real_rte_meter_trtcm_profile_config(profile, params);
}

int __wrap_rte_meter_trtcm_config(void *meter, void *profile) {
	return __real_rte_meter_trtcm_config(meter, profile);
}

// Mock the meter check to control test outcomes.
enum rte_color storm_control_meter_check(
	struct rte_meter_trtcm *m,
	struct rte_meter_trtcm_profile *p,
	uint64_t time,
	uint32_t pkt_len
) {
	(void)m; (void)p; (void)time; (void)pkt_len;
	return (enum rte_color)mock_type(int);
}

static void test_config(void **state) {
	(void)state;
	struct storm_control_config cfg;

	assert_int_equal(storm_control_set_config(
		100, true, 1000, 500, 250, false, true, 5
	), 0);

	assert_int_equal(storm_control_get_config(100, &cfg), 0);
	assert_true(cfg.enabled);
	assert_int_equal(cfg.bcast_rate_kbps, 1000);
	assert_int_equal(cfg.mcast_rate_kbps, 500);
	assert_int_equal(cfg.unknown_uc_rate_kbps, 250);
	assert_true(cfg.shutdown_on_violation);
	assert_int_equal(cfg.violation_threshold, 5);

	assert_int_equal(storm_control_set_config(
		L2_MAX_IFACES, true, 0, 0, 0, false, false, 5
	), -EINVAL);
	assert_int_equal(storm_control_get_config(L2_MAX_IFACES, &cfg), -EINVAL);
}

static void test_init_meters(void **state) {
	(void)state;

	storm_control_set_config(50, true, 1000, 500, 250, false, false, 5);

	assert_int_equal(storm_control_init_meters(50, 0), 0);

	struct storm_control_state *st = &storm_control_states[50][0];
	assert_int_equal(st->bcast_violations, 0);
	assert_false(st->is_shutdown);

	assert_int_equal(storm_control_init_meters(L2_MAX_IFACES, 0), -EINVAL);
	assert_int_equal(storm_control_init_meters(50, RTE_MAX_LCORE), -EINVAL);
}

static void test_meter_pass(void **state) {
	(void)state;

	storm_control_set_config(10, true, 1000000, 1000000, 1000000, false, false, 5);
	storm_control_init_meters(10, 0);

	will_return(storm_control_meter_check, 0); // GREEN
	assert_true(storm_control_meter_packet(10, 0, STORM_TRAFFIC_BROADCAST, 1500));

	will_return(storm_control_meter_check, 0);
	assert_true(storm_control_meter_packet(10, 0, STORM_TRAFFIC_MULTICAST, 1500));

	will_return(storm_control_meter_check, 0);
	assert_true(storm_control_meter_packet(10, 0, STORM_TRAFFIC_UNKNOWN_UC, 1500));

	struct storm_control_stats *stats = storm_control_get_stats(0, 10);
	assert_int_equal(stats->bcast_passed, 1);
	assert_int_equal(stats->mcast_passed, 1);
	assert_int_equal(stats->unknown_uc_passed, 1);
	assert_int_equal(stats->bcast_dropped, 0);
}

static void test_meter_drop(void **state) {
	(void)state;

	storm_control_set_config(20, true, 10, 10, 10, false, false, 10);
	storm_control_init_meters(20, 0);

	for (int i = 0; i < 10; i++) {
		will_return(storm_control_meter_check, i < 3 ? 0 : 2);
		bool r = storm_control_meter_packet(20, 0, STORM_TRAFFIC_BROADCAST, 100000);
		if (i < 3)
			assert_true(r);
		else
			assert_false(r);
	}

	struct storm_control_stats *stats = storm_control_get_stats(0, 20);
	assert_int_equal(stats->bcast_passed, 3);
	assert_int_equal(stats->bcast_dropped, 7);
}

static void test_shutdown(void **state) {
	(void)state;

	storm_control_set_config(30, true, 1, 1, 1, false, true, 3);
	storm_control_init_meters(30, 0);

	for (int i = 0; i < 10; i++) {
		if (i < 3)
			will_return(storm_control_meter_check, 2); // RED
		storm_control_meter_packet(30, 0, STORM_TRAFFIC_BROADCAST, 1000000);
	}

	assert_true(storm_control_states[30][0].is_shutdown);
	assert_true(storm_control_get_stats(0, 30)->shutdown_events > 0);

	assert_int_equal(storm_control_reenable_interface(30), 0);
	assert_false(storm_control_states[30][0].is_shutdown);
}

static void test_disabled(void **state) {
	(void)state;

	storm_control_set_config(40, false, 0, 0, 0, false, false, 5);

	assert_true(storm_control_meter_packet(40, 0, STORM_TRAFFIC_BROADCAST, 1500));
	assert_true(storm_control_meter_packet(40, 0, STORM_TRAFFIC_MULTICAST, 1500));

	struct storm_control_stats *stats = storm_control_get_stats(0, 40);
	assert_int_equal(stats->bcast_passed, 0);
}

static void test_invalid(void **state) {
	(void)state;

	assert_true(storm_control_meter_packet(L2_MAX_IFACES, 0, STORM_TRAFFIC_BROADCAST, 1500));
	assert_true(storm_control_meter_packet(10, RTE_MAX_LCORE, STORM_TRAFFIC_BROADCAST, 1500));
	assert_int_equal(storm_control_reenable_interface(L2_MAX_IFACES), -EINVAL);
	assert_null(storm_control_get_stats(RTE_MAX_LCORE, 10));
	assert_null(storm_control_get_stats(0, L2_MAX_IFACES));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_config),
		cmocka_unit_test(test_init_meters),
		cmocka_unit_test(test_meter_pass),
		cmocka_unit_test(test_meter_drop),
		cmocka_unit_test(test_shutdown),
		cmocka_unit_test(test_disabled),
		cmocka_unit_test(test_invalid),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
