// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "_cmocka.h"
#include "config.h"
#include "event.h"
#include "log.h"
#include "module.h"
#include "mpls.h"
#include "mpls_datapath.h"

#include <gr_mpls.h>

#include <rte_mpls.h>

// Global variables declared extern in log.h; defined here for the test binary.
int gr_rte_log_type;
struct log_types log_types = STAILQ_HEAD_INITIALIZER(log_types);
struct gr_config gr_config;

// Stubs for functions used by label_table.c and nexthop.c that are not under
// test. The prototypes are provided by the included headers above.
void module_register(struct module *) { }
void event_push(uint32_t, const void *) { }
void event_subscribe(uint32_t, event_sub_cb_t) { }
void nexthop_incref(struct nexthop *) { }
void nexthop_decref(struct nexthop *) { }
void nexthop_type_ops_register(gr_nh_type_t, const struct nexthop_type_ops *) { }
void vrf_fib_ops_register(addr_family_t, const struct vrf_fib_ops *) { }
struct nexthop *nexthop_new(const struct gr_nexthop_base *, const void *) {
	return NULL;
}
struct nexthop *nexthop_lookup_l3(addr_family_t, uint16_t, uint16_t, const void *) {
	return NULL;
}
void nexthop_iter(nh_iter_cb_t, void *) { }
struct iface *iface_from_id(uint16_t) {
	return NULL;
}

// rte_zmalloc wrapped to avoid DPDK EAL init in tests; forward declarations
// satisfy -Wmissing-prototypes before the definitions.
void *__wrap_rte_zmalloc(const char *, size_t size, unsigned /*align*/);
void *__wrap_rte_zmalloc(const char *, size_t size, unsigned /*align*/) {
	return calloc(1, size);
}
void __wrap_rte_free(void *ptr);
void __wrap_rte_free(void *ptr) {
	free(ptr);
}

// Fake VRF iface: the flexible array trick lets iface_info_vrf(&fake_vrf.iface)
// point directly at the embedded vrf member.
static struct {
	struct iface iface;
	struct iface_info_vrf vrf;
} fake_vrf;

struct iface *get_vrf_iface(uint16_t) {
	return &fake_vrf.iface;
}

static void test_label_encode_decode(void **) {
	static const uint32_t labels[] = {0, 15, 16, 100, 0xFFFFF};
	for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
		struct rte_mpls_hdr h = {};
		h.bs = 1;
		h.tc = 7;
		mpls_hdr_set_label(&h, labels[i]);
		assert_int_equal(mpls_hdr_get_label(&h), labels[i]);
		assert_int_equal(h.bs, 1);
		assert_int_equal(h.tc, 7);
	}
}

static void test_label_split(void **) {
	struct rte_mpls_hdr h = {};
	mpls_hdr_set_label(&h, 0x12345);
	assert_int_equal(h.tag_lsb, 0x5);
	assert_int_equal(mpls_hdr_get_label(&h), 0x12345);

	mpls_hdr_set_label(&h, 0);
	assert_int_equal(h.tag_lsb, 0);
	assert_int_equal(mpls_hdr_get_label(&h), 0);
}

static int lfib_setup(void **) {
	size_t sz;

	memset(&fake_vrf, 0, sizeof(fake_vrf));
	fake_vrf.iface.type = GR_IFACE_TYPE_VRF;
	sz = (GR_MPLS_LABEL_MAX + 1) * sizeof(struct nexthop *);
	iface_info_vrf(&fake_vrf.iface)->fib_mpls = calloc(1, sz);
	return 0;
}

static int lfib_teardown(void **) {
	free(iface_info_vrf(&fake_vrf.iface)->fib_mpls);
	iface_info_vrf(&fake_vrf.iface)->fib_mpls = NULL;
	return 0;
}

static void test_lfib_insert_lookup(void **) {
	struct nexthop nh = {};
	nh.origin = GR_NH_ORIGIN_ZSTATIC;

	assert_int_equal(mpls_rib_insert(1, 100, &nh, GR_NH_ORIGIN_ZSTATIC, false), 0);
	assert_ptr_equal(mpls_fib_lookup(1, 100), &nh);
	assert_null(mpls_fib_lookup(1, 101));
}

static void test_lfib_insert_duplicate(void **) {
	struct nexthop nh = {};
	nh.origin = GR_NH_ORIGIN_ZSTATIC;

	assert_int_equal(mpls_rib_insert(1, 200, &nh, GR_NH_ORIGIN_ZSTATIC, false), 0);
	assert_int_equal(mpls_rib_insert(1, 200, &nh, GR_NH_ORIGIN_ZSTATIC, true), 0);
	assert_int_equal(mpls_rib_insert(1, 200, &nh, GR_NH_ORIGIN_ZSTATIC, false), -EEXIST);
}

static void test_lfib_delete(void **) {
	struct nexthop nh = {};
	nh.origin = GR_NH_ORIGIN_ZSTATIC;

	assert_int_equal(mpls_rib_insert(1, 300, &nh, GR_NH_ORIGIN_ZSTATIC, false), 0);
	assert_int_equal(mpls_rib_delete(1, 300, false), 0);
	assert_null(mpls_fib_lookup(1, 300));
	assert_int_equal(mpls_rib_delete(1, 300, true), 0);
	assert_int_equal(mpls_rib_delete(1, 300, false), -ENOENT);
}

static int g_iter_count;
static int count_cb(uint16_t, uint32_t, const struct nexthop *, void *) {
	g_iter_count++;
	return 0;
}

static void test_lfib_iter(void **) {
	struct nexthop nh = {};
	nh.origin = GR_NH_ORIGIN_ZSTATIC;

	assert_int_equal(mpls_rib_insert(1, 400, &nh, GR_NH_ORIGIN_ZSTATIC, false), 0);
	assert_int_equal(mpls_rib_insert(1, 401, &nh, GR_NH_ORIGIN_ZSTATIC, false), 0);
	assert_int_equal(mpls_rib_insert(1, 402, &nh, GR_NH_ORIGIN_ZSTATIC, false), 0);

	g_iter_count = 0;
	assert_int_equal(mpls_rib_iter(1, count_cb, NULL), 0);
	assert_int_equal(g_iter_count, 3);
}

static void test_lfib_label_invalid(void **) {
	struct nexthop nh = {};
	uint32_t bad;

	bad = GR_MPLS_LABEL_MAX + 1;

	assert_int_equal(mpls_rib_insert(1, bad, &nh, GR_NH_ORIGIN_ZSTATIC, false), -EINVAL);
	assert_null(mpls_fib_lookup(1, bad));
	assert_int_equal(mpls_rib_delete(1, bad, false), -EINVAL);
}

extern bool mpls_nh_equal_test(const struct nexthop *, const struct nexthop *);

static void test_nh_equal_identical(void **) {
	struct nexthop a = {}, b = {};
	a.type = GR_NH_T_MPLS;
	b.type = GR_NH_T_MPLS;
	struct nexthop_info_mpls *ma = nexthop_info_mpls(&a);
	struct nexthop_info_mpls *mb = nexthop_info_mpls(&b);

	ma->n_labels = 1;
	ma->labels[0] = 100;
	ma->payload_af = GR_AF_UNSPEC;
	ma->via_nh = NULL;
	memcpy(mb, ma, sizeof(*mb));

	assert_true(mpls_nh_equal_test(&a, &b));
}

static void test_nh_equal_different_n_labels(void **) {
	struct nexthop a = {}, b = {};
	a.type = GR_NH_T_MPLS;
	b.type = GR_NH_T_MPLS;
	struct nexthop_info_mpls *ma = nexthop_info_mpls(&a);
	struct nexthop_info_mpls *mb = nexthop_info_mpls(&b);

	ma->n_labels = 1;
	ma->labels[0] = 100;
	mb->n_labels = 2;
	mb->labels[0] = 100;
	mb->labels[1] = 200;

	assert_false(mpls_nh_equal_test(&a, &b));
}

static void test_nh_equal_different_label(void **) {
	struct nexthop a = {}, b = {};
	a.type = GR_NH_T_MPLS;
	b.type = GR_NH_T_MPLS;
	struct nexthop_info_mpls *ma = nexthop_info_mpls(&a);
	struct nexthop_info_mpls *mb = nexthop_info_mpls(&b);

	ma->n_labels = 1;
	ma->labels[0] = 100;
	mb->n_labels = 1;
	mb->labels[0] = 200;

	assert_false(mpls_nh_equal_test(&a, &b));
}

static void test_nh_equal_different_payload_af(void **) {
	struct nexthop a = {}, b = {};
	a.type = GR_NH_T_MPLS;
	b.type = GR_NH_T_MPLS;
	struct nexthop_info_mpls *ma = nexthop_info_mpls(&a);
	struct nexthop_info_mpls *mb = nexthop_info_mpls(&b);

	ma->n_labels = 1;
	ma->labels[0] = 100;
	ma->payload_af = GR_AF_IP4;
	mb->n_labels = 1;
	mb->labels[0] = 100;
	mb->payload_af = GR_AF_IP6;

	assert_false(mpls_nh_equal_test(&a, &b));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		// Group A: header encoding
		cmocka_unit_test(test_label_encode_decode),
		cmocka_unit_test(test_label_split),
		// Group B: LFIB operations
		cmocka_unit_test_setup_teardown(test_lfib_insert_lookup, lfib_setup, lfib_teardown),
		cmocka_unit_test_setup_teardown(
			test_lfib_insert_duplicate, lfib_setup, lfib_teardown
		),
		cmocka_unit_test_setup_teardown(test_lfib_delete, lfib_setup, lfib_teardown),
		cmocka_unit_test_setup_teardown(test_lfib_iter, lfib_setup, lfib_teardown),
		cmocka_unit_test_setup_teardown(test_lfib_label_invalid, lfib_setup, lfib_teardown),
		// Group C: nexthop equality
		cmocka_unit_test(test_nh_equal_identical),
		cmocka_unit_test(test_nh_equal_different_n_labels),
		cmocka_unit_test(test_nh_equal_different_label),
		cmocka_unit_test(test_nh_equal_different_payload_af),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
