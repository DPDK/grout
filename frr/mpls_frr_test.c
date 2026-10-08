// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Matej Muzila

#include "rt_grout.h"

#include <gr_mpls.h>
#include <gr_nexthop.h>

#include <lib/mpls.h>
#include <lib/nexthop.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <zebra/zebra_mpls.h>

#include <cmocka.h>

// Forward declarations matching if_map.h so -Wmissing-prototypes is satisfied.
// These stubs replace if_map.c which is not linked into the test binary.
uint16_t ifindex_frr_to_grout(ifindex_t);
uint16_t vrf_frr_to_grout(vrf_id_t);

uint16_t ifindex_frr_to_grout(ifindex_t) {
	return 0;
}
uint16_t vrf_frr_to_grout(vrf_id_t) {
	return 0;
}

static void test_lsptype2origin(void **) {
	assert_int_equal(lsptype2origin(ZEBRA_LSP_STATIC), GR_NH_ORIGIN_ZSTATIC);
	assert_int_equal(lsptype2origin(ZEBRA_LSP_LDP), GR_NH_ORIGIN_LDP);
	assert_int_equal(lsptype2origin(ZEBRA_LSP_BGP), GR_NH_ORIGIN_BGP);
	assert_int_equal(lsptype2origin(ZEBRA_LSP_OSPF_SR), GR_NH_ORIGIN_OSPF);
	assert_int_equal(lsptype2origin(ZEBRA_LSP_ISIS_SR), GR_NH_ORIGIN_ISIS);
	assert_int_equal(lsptype2origin(ZEBRA_LSP_SHARP), GR_NH_ORIGIN_SHARP);
	assert_int_equal(lsptype2origin(ZEBRA_LSP_SRTE), GR_NH_ORIGIN_SRTE);
	assert_int_equal(lsptype2origin(ZEBRA_LSP_NONE), GR_NH_ORIGIN_ZEBRA);
	assert_int_equal(lsptype2origin(ZEBRA_LSP_EVPN), GR_NH_ORIGIN_ZEBRA);
}

static void test_nh_has_mpls_labels_null_label(void **) {
	struct nexthop nh = {};

	assert_false(nh_has_mpls_labels(&nh));
}

static void test_nh_has_mpls_labels_zero_count(void **) {
	struct mpls_label_stack nhl = {.num_labels = 0};
	struct nexthop nh = {};

	nh.nh_label = &nhl;
	assert_false(nh_has_mpls_labels(&nh));
}

static void test_nh_has_mpls_labels_implicit_null(void **) {
	struct mpls_label_stack *nhl;
	struct nexthop nh = {};

	nhl = malloc(sizeof(*nhl) + sizeof(mpls_label_t));

	assert_non_null(nhl);
	nhl->num_labels = 1;
	nhl->label[0] = MPLS_LABEL_IMPLICIT_NULL;
	nh.nh_label = nhl;
	assert_false(nh_has_mpls_labels(&nh));
	free(nhl);
}

static void test_nh_has_mpls_labels_real_label(void **) {
	struct mpls_label_stack *nhl;
	struct nexthop nh = {};

	nhl = malloc(sizeof(*nhl) + sizeof(mpls_label_t));

	assert_non_null(nhl);
	nhl->num_labels = 1;
	nhl->label[0] = 100;
	nh.nh_label = nhl;
	assert_true(nh_has_mpls_labels(&nh));
	free(nhl);
}

static void test_nh_has_mpls_labels_two_labels(void **) {
	struct mpls_label_stack *nhl;
	struct nexthop nh = {};

	nhl = malloc(sizeof(*nhl) + 2 * sizeof(mpls_label_t));

	assert_non_null(nhl);
	nhl->num_labels = 2;
	nhl->label[0] = 100;
	nhl->label[1] = 200;
	nh.nh_label = nhl;
	assert_true(nh_has_mpls_labels(&nh));
	free(nhl);
}

static void test_fill_mpls_nh_ipv4_one_label(void **) {
	struct gr_nexthop_info_mpls *mpls;
	struct mpls_label_stack *nhl;
	struct gr_nh_add_req *req;
	struct nexthop nh = {};
	size_t len;

	len = sizeof(struct gr_nh_add_req) + sizeof(struct gr_nexthop_info_mpls);
	req = calloc(1, len);
	mpls = (struct gr_nexthop_info_mpls *)req->nh.info;
	nhl = malloc(sizeof(*nhl) + sizeof(mpls_label_t));

	assert_non_null(req);

	nh.type = NEXTHOP_TYPE_IPV4_IFINDEX;
	nh.gate.ipv4.s_addr = htonl(0xAC100102);

	assert_non_null(nhl);
	nhl->num_labels = 1;
	nhl->label[0] = 100;
	nh.nh_label = nhl;

	assert_int_equal(grout_fill_mpls_nh(req, 42, GR_NH_ORIGIN_ZSTATIC, &nh), 0);

	assert_int_equal(mpls->via.af, GR_AF_IP4);
	assert_int_equal(mpls->n_labels, 1);
	assert_int_equal(mpls->labels[0], 100);
	assert_int_equal(mpls->ttl, 0);
	assert_int_equal(mpls->payload_af, GR_AF_UNSPEC);
	assert_true(req->exist_ok);
	assert_int_equal(req->nh.nh_id, 42);
	assert_int_equal(req->nh.origin, GR_NH_ORIGIN_ZSTATIC);
	assert_int_equal(req->nh.type, GR_NH_T_MPLS);

	free(nhl);
	free(req);
}

static void test_fill_mpls_nh_ipv6_two_labels(void **) {
	struct gr_nexthop_info_mpls *mpls;
	struct mpls_label_stack *nhl;
	struct gr_nh_add_req *req;
	struct nexthop nh = {};
	size_t len;

	len = sizeof(struct gr_nh_add_req) + sizeof(struct gr_nexthop_info_mpls);
	req = calloc(1, len);
	mpls = (struct gr_nexthop_info_mpls *)req->nh.info;
	nhl = malloc(sizeof(*nhl) + 2 * sizeof(mpls_label_t));

	assert_non_null(req);

	nh.type = NEXTHOP_TYPE_IPV6_IFINDEX;
	nh.gate.ipv6.s6_addr[0] = 0xfe;
	nh.gate.ipv6.s6_addr[1] = 0x80;
	nh.gate.ipv6.s6_addr[15] = 0x01;

	assert_non_null(nhl);
	nhl->num_labels = 2;
	nhl->label[0] = 200;
	nhl->label[1] = 100;
	nh.nh_label = nhl;

	assert_int_equal(grout_fill_mpls_nh(req, 43, GR_NH_ORIGIN_BGP, &nh), 0);

	assert_int_equal(mpls->via.af, GR_AF_IP6);
	assert_int_equal(mpls->n_labels, 2);
	assert_int_equal(mpls->labels[0], 200);
	assert_int_equal(mpls->labels[1], 100);

	free(nhl);
	free(req);
}

static void test_fill_mpls_nh_too_many_labels(void **) {
	struct mpls_label_stack *nhl;
	struct gr_nh_add_req *req;
	struct nexthop nh = {};
	size_t len;
	uint8_t n;

	n = GR_MPLS_MAX_LABELS + 1;
	len = sizeof(struct gr_nh_add_req) + sizeof(struct gr_nexthop_info_mpls);
	req = calloc(1, len);
	nhl = malloc(sizeof(*nhl) + n * sizeof(mpls_label_t));

	assert_non_null(req);

	nh.type = NEXTHOP_TYPE_IPV4;
	nh.gate.ipv4.s_addr = htonl(0xAC100102);

	assert_non_null(nhl);
	nhl->num_labels = n;
	for (uint8_t i = 0; i < n; i++)
		nhl->label[i] = 100 + i;
	nh.nh_label = nhl;

	assert_int_equal(grout_fill_mpls_nh(req, 44, GR_NH_ORIGIN_ZSTATIC, &nh), -1);

	free(nhl);
	free(req);
}

static void test_fill_mpls_nh_unsupported_type(void **) {
	struct gr_nh_add_req *req;
	struct nexthop nh = {};
	size_t len;

	len = sizeof(struct gr_nh_add_req) + sizeof(struct gr_nexthop_info_mpls);
	req = calloc(1, len);

	assert_non_null(req);

	nh.type = NEXTHOP_TYPE_BLACKHOLE;

	assert_int_equal(grout_fill_mpls_nh(req, 45, GR_NH_ORIGIN_ZSTATIC, &nh), -1);

	free(req);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_lsptype2origin),
		cmocka_unit_test(test_nh_has_mpls_labels_null_label),
		cmocka_unit_test(test_nh_has_mpls_labels_zero_count),
		cmocka_unit_test(test_nh_has_mpls_labels_implicit_null),
		cmocka_unit_test(test_nh_has_mpls_labels_real_label),
		cmocka_unit_test(test_nh_has_mpls_labels_two_labels),
		cmocka_unit_test(test_fill_mpls_nh_ipv4_one_label),
		cmocka_unit_test(test_fill_mpls_nh_ipv6_two_labels),
		cmocka_unit_test(test_fill_mpls_nh_too_many_labels),
		cmocka_unit_test(test_fill_mpls_nh_unsupported_type),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
