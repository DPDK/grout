// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include "vlan_filtering_priv.h"

#include <gr_cmocka.h>
#include <gr_log.h>

#include <stdlib.h>
#include <string.h>

int gr_rte_log_type;

// Mocked functions.
void gr_register_api_handler(struct gr_api_handler *) { }
struct iface *iface_from_id(uint16_t) { return NULL; }
struct vlan_filtering *bridge_get_vlan_filtering(const struct iface *bridge) {
	(void)bridge;
	return NULL;
}

void *__wrap_rte_zmalloc(const char *type, size_t size, unsigned align) {
	(void)type; (void)align;
	return calloc(1, size);
}

void __wrap_rte_free(void *ptr) { free(ptr); }

static void test_alloc_free(void **state) {
	(void)state;
	struct vlan_filtering *vf = vlan_filtering_alloc();
	assert_non_null(vf);
	assert_false(vf->enabled);

	assert_int_equal(vf->port_configs[0].mode, PORT_VLAN_MODE_ACCESS);
	assert_int_equal(vf->port_configs[0].access_vlan, 1);
	assert_true(vf->port_configs[0].pvid_enabled);
	assert_true(vlan_is_allowed(vf->port_configs[0].allowed_vlans, 1));
	assert_false(vlan_is_allowed(vf->port_configs[0].allowed_vlans, 100));

	vlan_filtering_free(vf);
}

static void test_access_mode(void **state) {
	(void)state;
	struct vlan_filtering *vf = vlan_filtering_alloc();
	assert_non_null(vf);

	assert_int_equal(vlan_port_set_access(vf, 5, 100), 0);
	assert_int_equal(vf->port_configs[5].mode, PORT_VLAN_MODE_ACCESS);
	assert_int_equal(vf->port_configs[5].access_vlan, 100);
	assert_true(vlan_is_allowed(vf->port_configs[5].allowed_vlans, 100));
	assert_false(vlan_is_allowed(vf->port_configs[5].allowed_vlans, 1));

	assert_int_equal(vlan_port_set_access(vf, 5, 0), -EINVAL);
	assert_int_equal(vlan_port_set_access(vf, 5, 4095), -EINVAL);

	vlan_filtering_free(vf);
}

static void test_trunk_mode(void **state) {
	(void)state;
	struct vlan_filtering *vf = vlan_filtering_alloc();
	uint16_t vlans[] = {10, 20, 30, 100};

	assert_int_equal(vlan_port_set_trunk(vf, 10, 1, vlans, 4), 0);
	assert_int_equal(vf->port_configs[10].mode, PORT_VLAN_MODE_TRUNK);
	assert_int_equal(vf->port_configs[10].native_vlan, 1);
	assert_true(vf->port_configs[10].pvid_enabled);
	assert_true(vlan_is_allowed(vf->port_configs[10].allowed_vlans, 1));
	assert_true(vlan_is_allowed(vf->port_configs[10].allowed_vlans, 10));
	assert_true(vlan_is_allowed(vf->port_configs[10].allowed_vlans, 100));
	assert_false(vlan_is_allowed(vf->port_configs[10].allowed_vlans, 50));

	// Allow all when num_vlans == 0
	assert_int_equal(vlan_port_set_trunk(vf, 11, 0, NULL, 0), 0);
	assert_false(vf->port_configs[11].pvid_enabled);
	assert_true(vlan_is_allowed(vf->port_configs[11].allowed_vlans, 1));
	assert_true(vlan_is_allowed(vf->port_configs[11].allowed_vlans, 4094));

	vlan_filtering_free(vf);
}

static void test_translation(void **state) {
	(void)state;
	struct vlan_filtering *vf = vlan_filtering_alloc();

	assert_int_equal(vlan_port_set_translation(vf, 5, 100, 200), 0);
	assert_true(vf->port_configs[5].translation.ingress_enabled);
	assert_int_equal(vf->port_configs[5].translation.ingress_outer_vlan, 100);
	assert_int_equal(vf->port_configs[5].translation.ingress_inner_vlan, 200);

	assert_int_equal(vlan_port_clear_translation(vf, 5), 0);
	assert_false(vf->port_configs[5].translation.ingress_enabled);
	assert_false(vf->port_configs[5].translation.egress_enabled);
	assert_false(vf->port_configs[5].translation.qinq_enabled);

	assert_int_equal(vlan_port_set_translation(vf, 5, 4095, 200), -EINVAL);

	vlan_filtering_free(vf);
}

static void test_qinq(void **state) {
	(void)state;
	struct vlan_filtering *vf = vlan_filtering_alloc();

	assert_int_equal(vlan_port_set_qinq(vf, 5, 500), 0);
	assert_true(vf->port_configs[5].translation.qinq_enabled);
	assert_int_equal(vf->port_configs[5].translation.qinq_svid, 500);

	assert_int_equal(vlan_port_clear_qinq(vf, 5), 0);
	assert_false(vf->port_configs[5].translation.qinq_enabled);

	vlan_filtering_free(vf);
}

static void test_ingress_access(void **state) {
	(void)state;
	struct vlan_filtering *vf = vlan_filtering_alloc();
	vf->enabled = true;

	vlan_port_set_access(vf, 5, 100);

	assert_true(vlan_ingress_check(vf, 5, 0, false));
	assert_true(vlan_ingress_check(vf, 5, 100, true));
	assert_false(vlan_ingress_check(vf, 5, 200, true));

	vlan_filtering_free(vf);
}

static void test_ingress_trunk(void **state) {
	(void)state;
	struct vlan_filtering *vf = vlan_filtering_alloc();
	uint16_t vlans[] = {10, 20, 30};
	vf->enabled = true;

	vlan_port_set_trunk(vf, 10, 1, vlans, 3);

	assert_true(vlan_ingress_check(vf, 10, 0, false));
	assert_true(vlan_ingress_check(vf, 10, 10, true));
	assert_false(vlan_ingress_check(vf, 10, 100, true));

	// No native VLAN: untagged dropped
	vlan_port_set_trunk(vf, 11, 0, vlans, 3);
	assert_false(vlan_ingress_check(vf, 11, 0, false));
	assert_true(vlan_ingress_check(vf, 11, 10, true));

	vlan_filtering_free(vf);
}

static void test_egress(void **state) {
	(void)state;
	struct vlan_filtering *vf = vlan_filtering_alloc();
	uint16_t vlans[] = {10, 20, 30};
	bool untag;
	vf->enabled = true;

	// Access mode: always untag
	vlan_port_set_access(vf, 5, 100);
	assert_true(vlan_egress_check(vf, 5, 100, &untag));
	assert_true(untag);
	assert_false(vlan_egress_check(vf, 5, 200, &untag));

	// Trunk mode: untag native only
	vlan_port_set_trunk(vf, 10, 1, vlans, 3);
	assert_true(vlan_egress_check(vf, 10, 1, &untag));
	assert_true(untag);
	assert_true(vlan_egress_check(vf, 10, 10, &untag));
	assert_false(untag);
	assert_false(vlan_egress_check(vf, 10, 100, &untag));

	vlan_filtering_free(vf);
}

static void test_bitmap(void **state) {
	(void)state;
	uint64_t bitmap[VLAN_BITMAP_SIZE] = {0};

	assert_false(vlan_is_allowed(bitmap, 1));
	vlan_allow(bitmap, 1);
	assert_true(vlan_is_allowed(bitmap, 1));
	assert_false(vlan_is_allowed(bitmap, 2));

	vlan_allow(bitmap, 4094);
	assert_true(vlan_is_allowed(bitmap, 4094));

	vlan_disallow(bitmap, 1);
	assert_false(vlan_is_allowed(bitmap, 1));
	assert_true(vlan_is_allowed(bitmap, 4094));

	vlan_allow_all(bitmap);
	assert_true(vlan_is_allowed(bitmap, 1));
	assert_true(vlan_is_allowed(bitmap, 2000));

	vlan_clear_all(bitmap);
	assert_false(vlan_is_allowed(bitmap, 1));

	assert_false(vlan_is_allowed(bitmap, 0));
	assert_false(vlan_is_allowed(bitmap, 4095));
}

static void test_disabled(void **state) {
	(void)state;
	struct vlan_filtering *vf = vlan_filtering_alloc();
	bool untag;
	vf->enabled = false;

	vlan_port_set_access(vf, 5, 100);

	assert_true(vlan_ingress_check(vf, 5, 200, true));
	assert_true(vlan_egress_check(vf, 5, 200, &untag));
	assert_true(vlan_ingress_check(NULL, 5, 100, true));
	assert_true(vlan_egress_check(NULL, 5, 100, &untag));

	vlan_filtering_free(vf);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_alloc_free),
		cmocka_unit_test(test_access_mode),
		cmocka_unit_test(test_trunk_mode),
		cmocka_unit_test(test_translation),
		cmocka_unit_test(test_qinq),
		cmocka_unit_test(test_ingress_access),
		cmocka_unit_test(test_ingress_trunk),
		cmocka_unit_test(test_egress),
		cmocka_unit_test(test_bitmap),
		cmocka_unit_test(test_disabled),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
