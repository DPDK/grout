// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include "port_mirror_priv.h"

#include <gr_cmocka.h>
#include <gr_log.h>

#include <stdlib.h>
#include <string.h>

int gr_rte_log_type;

// Mocked functions.
void gr_register_api_handler(struct gr_api_handler *) { }
struct iface *iface_from_id(uint16_t) { return NULL; }

static void test_session_set_get(void **state) {
	(void)state;
	struct mirror_session session;
	uint16_t sources[] = {10, 20, 30};

	assert_int_equal(port_mirror_session_set(
		0, 1, true, sources, 3, 50,
		GR_MIRROR_DIR_BOTH, false, 0
	), 0);

	assert_int_equal(port_mirror_session_get(0, 1, &session), 0);
	assert_true(session.enabled);
	assert_int_equal(session.dest_port, 50);
	assert_int_equal(session.direction, GR_MIRROR_DIR_BOTH);
	assert_int_equal(gr_vec_len(session.source_ports), 3);
	assert_false(session.is_rspan);
}

static void test_session_del(void **state) {
	(void)state;
	struct mirror_session session;
	uint16_t sources[] = {10};

	port_mirror_session_set(0, 2, true, sources, 1, 50,
		GR_MIRROR_DIR_INGRESS, false, 0);

	assert_int_equal(port_mirror_session_del(0, 2), 0);
	assert_int_equal(port_mirror_session_get(0, 2, &session), 0);
	assert_false(session.enabled);
}

static void test_session_rspan(void **state) {
	(void)state;
	struct mirror_session session;
	uint16_t sources[] = {10};

	assert_int_equal(port_mirror_session_set(
		0, 3, true, sources, 1, 50,
		GR_MIRROR_DIR_INGRESS, true, 100
	), 0);

	assert_int_equal(port_mirror_session_get(0, 3, &session), 0);
	assert_true(session.is_rspan);
	assert_int_equal(session.rspan_vlan, 100);

	port_mirror_session_del(0, 3);
}

static void test_should_mirror(void **state) {
	(void)state;
	uint16_t sources[] = {10, 20};
	uint16_t session_ids[MAX_MIRROR_SESSIONS];
	uint16_t num;

	port_mirror_session_set(1, 1, true, sources, 2, 50,
		GR_MIRROR_DIR_INGRESS, false, 0);

	assert_true(port_mirror_should_mirror(
		1, 10, GR_MIRROR_DIR_INGRESS, session_ids, &num
	));
	assert_int_equal(num, 1);
	assert_int_equal(session_ids[0], 1);

	// Wrong direction
	assert_false(port_mirror_should_mirror(
		1, 10, GR_MIRROR_DIR_EGRESS, session_ids, &num
	));

	// Not a source port
	assert_false(port_mirror_should_mirror(
		1, 99, GR_MIRROR_DIR_INGRESS, session_ids, &num
	));

	port_mirror_session_del(1, 1);
}

static void test_filter_set(void **state) {
	(void)state;
	struct mirror_session session;
	uint16_t sources[] = {10};
	uint16_t vlans[] = {100, 200};
	struct rte_ether_addr mac = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}};

	port_mirror_session_set(2, 1, true, sources, 1, 50,
		GR_MIRROR_DIR_BOTH, false, 0);

	assert_int_equal(port_mirror_filter_set(
		2, 1, true, vlans, 2, 0x0800, &mac, NULL
	), 0);

	port_mirror_session_get(2, 1, &session);
	assert_true(session.filter.enabled);
	assert_int_equal(session.filter.ether_type, 0x0800);
	assert_true(session.filter.src_mac_set);
	assert_false(session.filter.dst_mac_set);

	// Filter on non-existent session
	assert_int_equal(port_mirror_filter_set(2, 5, true, NULL, 0, 0, NULL, NULL), -ENOENT);

	port_mirror_session_del(2, 1);
}

static void test_invalid_params(void **state) {
	(void)state;
	struct mirror_session session;
	uint16_t sources[] = {10};

	assert_int_equal(port_mirror_session_set(
		L2_MAX_BRIDGES, 1, true, sources, 1, 50,
		GR_MIRROR_DIR_BOTH, false, 0
	), -EINVAL);

	assert_int_equal(port_mirror_session_set(
		0, 0, true, sources, 1, 50,
		GR_MIRROR_DIR_BOTH, false, 0
	), -EINVAL);

	assert_int_equal(port_mirror_session_set(
		0, MAX_MIRROR_SESSIONS + 1, true, sources, 1, 50,
		GR_MIRROR_DIR_BOTH, false, 0
	), -EINVAL);

	assert_int_equal(port_mirror_session_get(L2_MAX_BRIDGES, 1, &session), -EINVAL);
	assert_int_equal(port_mirror_session_del(L2_MAX_BRIDGES, 1), -EINVAL);

	assert_null(port_mirror_get_stats(RTE_MAX_LCORE, 0));
	assert_null(port_mirror_get_stats(0, L2_MAX_BRIDGES));
}

static void test_stats(void **state) {
	(void)state;

	struct mirror_stats *st = port_mirror_get_stats(0, 0);
	assert_non_null(st);
	st->packets_mirrored = 42;
	assert_int_equal(port_mirror_get_stats(0, 0)->packets_mirrored, 42);
	st->packets_mirrored = 0;
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_session_set_get),
		cmocka_unit_test(test_session_del),
		cmocka_unit_test(test_session_rspan),
		cmocka_unit_test(test_should_mirror),
		cmocka_unit_test(test_filter_set),
		cmocka_unit_test(test_invalid_params),
		cmocka_unit_test(test_stats),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
