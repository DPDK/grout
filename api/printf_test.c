// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_cmocka.h>
#include <gr_net_types.h>

#include <stddef.h>
#include <stdio.h>

static void ether(void **) {
	struct rte_ether_addr mac = {{0x90, 0x2e, 0x16, 0x55, 0x8e, 0x6a}};
	char buf[64];
	buf[0] = 0;
	snprintf(buf, sizeof(buf), ETH_F, &mac);
	assert_string_equal(buf, "90:2e:16:55:8e:6a");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), ETH_F, NULL);
	assert_string_equal(buf, "(nil)");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), ADDR_F, 2, &mac);
	assert_string_equal(buf, "90:2e:16:55:8e:6a");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), ADDR_F, 2, NULL);
	assert_string_equal(buf, "(nil)");
}

static void ipv4(void **) {
	ip4_addr_t ip4 = htonl(0x01020304);
	char buf[64];
	buf[0] = 0;
	snprintf(buf, sizeof(buf), IP4_F, &ip4);
	assert_string_equal(buf, "1.2.3.4");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), IP4_F, NULL);
	assert_string_equal(buf, "(nil)");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), ADDR_F, 4, &ip4);
	assert_string_equal(buf, "1.2.3.4");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), ADDR_F, 4, NULL);
	assert_string_equal(buf, "(nil)");
}

static void ipv6(void **) {
	struct rte_ipv6_addr ip6 = {
		{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x2e, 0x8b, 0x35, 0x2e, 0x66, 0xbf, 0x3a, 0xd8}
	};
	char buf[64];
	buf[0] = 0;
	snprintf(buf, sizeof(buf), IP6_F, &ip6);
	assert_string_equal(buf, "fe80::2e8b:352e:66bf:3ad8");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), IP6_F, NULL);
	assert_string_equal(buf, "(nil)");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), ADDR_F, 6, &ip6);
	assert_string_equal(buf, "fe80::2e8b:352e:66bf:3ad8");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), ADDR_F, 6, NULL);
	assert_string_equal(buf, "(nil)");
}

static void pointers(void **) {
	void *p = (void *)(uintptr_t)0x7ffd3aae340c;
	char buf[64];
	buf[0] = 0;
	snprintf(buf, sizeof(buf), "%p", p);
	assert_string_equal(buf, "0x7ffd3aae340c");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), "%1337p", p);
	assert_string_equal(buf, "0x7ffd3aae340c");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), "%42p", p);
	assert_string_equal(buf, "0x7ffd3aae340c");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), "%p", NULL);
	assert_string_equal(buf, "(nil)");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), "%1337p", NULL);
	assert_string_equal(buf, "(nil)");
	buf[0] = 0;
	snprintf(buf, sizeof(buf), "%42p", NULL);
	assert_string_equal(buf, "(nil)");
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ether),
		cmocka_unit_test(ipv4),
		cmocka_unit_test(ipv6),
		cmocka_unit_test(pointers),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
