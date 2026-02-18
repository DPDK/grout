// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include "mcast_snooping_priv.h"

#include <gr_cmocka.h>
#include <gr_log.h>

#include <string.h>

int gr_rte_log_type;

// Mocked functions.
void gr_register_api_handler(struct gr_api_handler *) { }
struct iface *iface_from_id(uint16_t) { return NULL; }
void api_send(struct api_ctx *, uint32_t, const void *) { }
struct mcast_snooping *bridge_get_mcast_snooping(const struct iface *bridge) {
	(void)bridge;
	return NULL;
}

static void test_ip4_to_mac(void **state) {
	(void)state;
	struct rte_ether_addr mac;

	// 224.1.2.3 → 01:00:5E:01:02:03
	ip4_addr_t ip4 = (224U << 24) | (1 << 16) | (2 << 8) | 3;
	mcast_ip_to_mac(&ip4, 4, &mac);
	assert_int_equal(mac.addr_bytes[0], 0x01);
	assert_int_equal(mac.addr_bytes[1], 0x00);
	assert_int_equal(mac.addr_bytes[2], 0x5E);
	assert_int_equal(mac.addr_bytes[3], 0x01);
	assert_int_equal(mac.addr_bytes[4], 0x02);
	assert_int_equal(mac.addr_bytes[5], 0x03);

	// 239.255.255.250 → 01:00:5E:7F:FF:FA
	ip4 = (239U << 24) | (255 << 16) | (255 << 8) | 250;
	mcast_ip_to_mac(&ip4, 4, &mac);
	assert_int_equal(mac.addr_bytes[0], 0x01);
	assert_int_equal(mac.addr_bytes[2], 0x5E);
	assert_int_equal(mac.addr_bytes[3], 0x7F);
	assert_int_equal(mac.addr_bytes[5], 0xFA);
}

static void test_ip6_to_mac(void **state) {
	(void)state;
	struct rte_ether_addr mac;

	// ff02::1 → 33:33:00:00:00:01
	struct rte_ipv6_addr ip6 = {
		.a = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	};
	mcast_ip_to_mac(&ip6, 6, &mac);
	assert_int_equal(mac.addr_bytes[0], 0x33);
	assert_int_equal(mac.addr_bytes[1], 0x33);
	assert_int_equal(mac.addr_bytes[2], 0x00);
	assert_int_equal(mac.addr_bytes[3], 0x00);
	assert_int_equal(mac.addr_bytes[4], 0x00);
	assert_int_equal(mac.addr_bytes[5], 0x01);

	// ff02::fb → 33:33:00:00:00:FB
	struct rte_ipv6_addr ip6b = {
		.a = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb}
	};
	mcast_ip_to_mac(&ip6b, 6, &mac);
	assert_int_equal(mac.addr_bytes[5], 0xFB);
}

static void test_stats_accessor(void **state) {
	(void)state;

	struct mcast_snoop_stats *st = mcast_snoop_get_stats(0, 0);
	assert_non_null(st);

	st->igmp_report_rx = 42;
	assert_int_equal(mcast_snoop_get_stats(0, 0)->igmp_report_rx, 42);
	st->igmp_report_rx = 0;

	assert_null(mcast_snoop_get_stats(RTE_MAX_LCORE, 0));
	assert_null(mcast_snoop_get_stats(0, L2_MAX_BRIDGES));
}

static void test_null_safety(void **state) {
	(void)state;

	// All functions should handle NULL gracefully.
	assert_null(mdb_lookup(NULL, NULL));
	assert_int_equal(mdb_add_entry(NULL, NULL, NULL, 4, 0, false), -EINVAL);
	assert_int_equal(mdb_del_entry(NULL, NULL, 0), -EINVAL);
	assert_int_equal(mdb_del_port(NULL, 0), -EINVAL);
	assert_int_equal(igmp_process_report(NULL, 0, NULL, 4), -EINVAL);
	assert_int_equal(igmp_process_leave(NULL, 0, NULL, 4), -EINVAL);

	// Aging with NULL should be safe.
	mdb_aging_tick(NULL, 0, 0);

	mcast_snooping_free(NULL);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ip4_to_mac),
		cmocka_unit_test(test_ip6_to_mac),
		cmocka_unit_test(test_stats_accessor),
		cmocka_unit_test(test_null_safety),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
