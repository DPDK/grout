// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_cmocka.h>
#include <gr_string.h>

#include <errno.h>
#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

#define assert_errno_equal(call, errnum)                                                           \
	do {                                                                                       \
		int ret = call;                                                                    \
		if (errnum == 0 && ret < 0)                                                        \
			fail_msg(                                                                  \
				"%s failed with %s, expected success",                             \
				#call,                                                             \
				strerrorname_np(errno)                                             \
			);                                                                         \
		else if (errnum != 0 && ret >= 0)                                                  \
			fail_msg(                                                                  \
				"%s succeeded, expected failure with %s",                          \
				#call,                                                             \
				strerrorname_np(errnum)                                            \
			);                                                                         \
		else if (ret < 0 && errno != errnum)                                               \
			fail_msg(                                                                  \
				"%s failed with %s, expected %s",                                  \
				#call,                                                             \
				strerrorname_np(errno),                                            \
				strerrorname_np(errnum)                                            \
			);                                                                         \
	} while (0)

static void format(void **) {
	cpu_set_t set;
	char buf[256];

	assert_errno_equal(cpuset_format(buf, sizeof(buf), NULL), EINVAL);
	assert_errno_equal(cpuset_format(NULL, 0, &set), EINVAL);

	CPU_ZERO(&set);
	assert_errno_equal(cpuset_format(buf, sizeof(buf), &set), 0);
	assert_string_equal(buf, "");

	CPU_SET(0, &set);
	assert_errno_equal(cpuset_format(buf, sizeof(buf), &set), 0);
	assert_string_equal(buf, "0");

	CPU_SET(42, &set);
	assert_errno_equal(cpuset_format(buf, sizeof(buf), &set), 0);
	assert_string_equal(buf, "0,42");

	for (int i = 3; i < 27; i++)
		CPU_SET(i, &set);
	for (int i = 77; i < 100; i++)
		CPU_SET(i, &set);
	assert_errno_equal(cpuset_format(buf, sizeof(buf), &set), 0);
	assert_string_equal(buf, "0,3-26,42,77-99");

	for (int i = 0; i < CPU_SETSIZE; i++)
		CPU_SET(i, &set);
	assert_errno_equal(cpuset_format(buf, sizeof(buf), &set), 0);
	assert_string_equal(buf, "0-1023");
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(format),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
