// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include "qos_priv.h"

#include <gr_cmocka.h>
#include <gr_log.h>

#include <string.h>

int gr_rte_log_type;

// Mocked functions.
void gr_register_api_handler(struct gr_api_handler *) { }
struct iface *iface_from_id(uint16_t) { return NULL; }

enum rte_color qos_meter_check(
	struct rte_meter_trtcm *m,
	struct rte_meter_trtcm_profile *p,
	uint64_t time,
	uint32_t pkt_len
) {
	(void)m; (void)p; (void)time; (void)pkt_len;
	return RTE_COLOR_GREEN;
}

static void test_port_set_get(void **state) {
	(void)state;
	struct qos_port_config cfg;

	assert_int_equal(qos_port_set(100, true, GR_QOS_SCHED_STRICT, 1000, true, false, 3), 0);
	assert_int_equal(qos_port_get(100, &cfg), 0);
	assert_true(cfg.enabled);
	assert_int_equal(cfg.sched_mode, GR_QOS_SCHED_STRICT);
	assert_int_equal(cfg.port_rate_limit_kbps, 1000);
	assert_true(cfg.trust_cos);
	assert_false(cfg.trust_dscp);
	assert_int_equal(cfg.default_priority, 3);

	assert_int_equal(qos_port_set(L2_MAX_IFACES, true, 0, 0, false, false, 0), -EINVAL);
	assert_int_equal(qos_port_set(0, true, 0, 0, false, false, 8), -EINVAL);
}

static void test_queue_set(void **state) {
	(void)state;

	assert_int_equal(qos_queue_set(100, 5, 500, 10, 100), 0);

	struct qos_port_config cfg;
	qos_port_get(100, &cfg);
	assert_int_equal(cfg.queues[5].rate_limit_kbps, 500);
	assert_int_equal(cfg.queues[5].weight, 10);
	assert_int_equal(cfg.queues[5].min_rate_kbps, 100);

	assert_int_equal(qos_queue_set(100, 8, 500, 10, 100), -EINVAL);
	assert_int_equal(qos_queue_set(100, 0, 500, 0, 100), -EINVAL);
	assert_int_equal(qos_queue_set(L2_MAX_IFACES, 0, 500, 1, 0), -EINVAL);
}

static void test_dscp_map(void **state) {
	(void)state;
	uint8_t map[64] = {0};

	map[46] = 6; // EF -> CoS 6
	assert_int_equal(qos_dscp_map_set(100, map), 0);

	struct qos_port_config cfg;
	qos_port_get(100, &cfg);
	assert_int_equal(cfg.dscp_to_cos[46], 6);

	map[0] = 8; // Invalid CoS
	assert_int_equal(qos_dscp_map_set(100, map), -EINVAL);
}

static void test_cos_remap(void **state) {
	(void)state;
	uint8_t remap[8] = {0, 1, 2, 3, 4, 5, 6, 7};

	remap[0] = 3; // Remap CoS 0 -> 3
	assert_int_equal(qos_cos_remap_set(100, remap), 0);

	struct qos_port_config cfg;
	qos_port_get(100, &cfg);
	assert_int_equal(cfg.cos_to_cos[0], 3);

	remap[0] = 8; // Invalid
	assert_int_equal(qos_cos_remap_set(100, remap), -EINVAL);
}

static void test_stats_accessor(void **state) {
	(void)state;

	struct qos_stats *st = qos_get_stats(0, 0);
	assert_non_null(st);
	st->tx[0] = 42;
	assert_int_equal(qos_get_stats(0, 0)->tx[0], 42);
	st->tx[0] = 0;

	assert_null(qos_get_stats(RTE_MAX_LCORE, 0));
	assert_null(qos_get_stats(0, L2_MAX_IFACES));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_port_set_get),
		cmocka_unit_test(test_queue_set),
		cmocka_unit_test(test_dscp_map),
		cmocka_unit_test(test_cos_remap),
		cmocka_unit_test(test_stats_accessor),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
