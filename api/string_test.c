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

	CPU_ZERO(&set);

	assert_errno_equal(cpuset_format(buf, sizeof(buf), NULL), EINVAL);
	assert_errno_equal(cpuset_format(NULL, 0, &set), EINVAL);

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

static void _assert_cpuset_equal(const char *s, const cpu_set_t *set, ...) {
	cpu_set_t expected, x, missing, extraneous;
	char buf[256];
	va_list ap;

	CPU_ZERO(&expected);
	va_start(ap, set);
	for (int cpu = va_arg(ap, int); cpu != -1; cpu = va_arg(ap, int))
		CPU_SET(cpu, &expected);
	va_end(ap);

	CPU_XOR(&x, set, &expected);

	CPU_AND(&missing, &x, &expected);
	if (CPU_COUNT(&missing) > 0) {
		cpuset_format(buf, sizeof(buf), &missing);
		fail_msg("cpuset_parse(\"%s\") missing cpus \"%s\"", s, buf);
	}

	CPU_AND(&extraneous, &x, set);
	if (CPU_COUNT(&extraneous) > 0) {
		cpuset_format(buf, sizeof(buf), &extraneous);
		fail_msg("cpuset_parse(\"%s\") extraneous cpus \"%s\"", s, buf);
	}
}

#define assert_cpuset_equal(s, set, ...) _assert_cpuset_equal(s, set, __VA_ARGS__, -1)

static void parse(void **) {
	cpu_set_t set;

	assert_errno_equal(cpuset_parse(&set, NULL), EINVAL);
	assert_errno_equal(cpuset_parse(&set, ""), EINVAL);
	assert_errno_equal(cpuset_parse(&set, "foobaz"), EINVAL);
	assert_errno_equal(cpuset_parse(&set, "--"), EINVAL);
	assert_errno_equal(cpuset_parse(&set, "2-,2"), EINVAL);
	assert_errno_equal(cpuset_parse(&set, "(╯°□°)╯︵ ʇnoɹƃ"), EINVAL);
	assert_errno_equal(cpuset_parse(&set, "\xba\xd0\xca\xca"), EINVAL);
	assert_errno_equal(cpuset_parse(&set, "21351"), EOVERFLOW);
	assert_errno_equal(cpuset_parse(&set, "10-5"), ERANGE);

	assert_errno_equal(cpuset_parse(&set, "5-10"), 0);
	assert_cpuset_equal("5-10", &set, 5, 6, 7, 8, 9, 10);

	assert_errno_equal(cpuset_parse(&set, "1,8,99-101"), 0);
	assert_cpuset_equal("1,8,99-101", &set, 1, 8, 99, 100, 101);

	assert_errno_equal(cpuset_parse(&set, "40-44,1,4-8,1,1"), 0);
	assert_cpuset_equal("40-44,1,1,1,4-8", &set, 1, 4, 5, 6, 7, 8, 40, 41, 42, 43, 44);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(format),
		cmocka_unit_test(parse),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
