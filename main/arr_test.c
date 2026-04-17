// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "_cmocka.h"
#include "arr.h"

static void int_arr(void **) {
	arr int *a = NULL;

	assert_int_equal(arr_len(a), 0);

	for (int i = 0; i < 5; i++)
		arr_add(a, i);

	assert_int_equal(arr_len(a), 5);

	for (int i = 0; i < 5; i++)
		assert_int_equal(a[i], i);

	arr_del(a, 0);
	assert_int_equal(arr_len(a), 4);
	for (int i = 0; i < 4; i++)
		assert_int_equal(a[i], i + 1);

	arr_insert(a, 0, 0);
	assert_int_equal(arr_len(a), 5);
	for (int i = 0; i < 5; i++)
		assert_int_equal(a[i], i);

	arr_insert(a, 1, 42);
	assert_int_equal(arr_len(a), 6);
	assert_int_equal(a[0], 0);
	assert_int_equal(a[1], 42);
	assert_int_equal(a[2], 1);
	assert_int_equal(a[3], 2);
	assert_int_equal(a[4], 3);
	assert_int_equal(a[5], 4);

	arr_del_swap(a, 3);
	assert_int_equal(arr_len(a), 5);

	assert_int_equal(arr_pop(a), 3);
	assert_int_equal(arr_pop(a), 4);
	assert_int_equal(arr_pop(a), 1);
	assert_int_equal(arr_pop(a), 42);

	arr_del_swap(a, 0);
	assert_int_equal(arr_len(a), 0);

	arr_free(a);
}

static void str_arr(void **) {
	arr const char **a = NULL;

	assert_int_equal(arr_len(a), 0);

	arr_add(a, "foo");
	arr_add(a, "bar");
	arr_add(a, "baz");

	assert_int_equal(arr_len(a), 3);
	assert_string_equal(a[0], "foo");
	assert_string_equal(a[1], "bar");
	assert_string_equal(a[2], "baz");

	arr_del(a, 1);

	assert_int_equal(arr_len(a), 2);
	assert_string_equal(a[0], "foo");
	assert_string_equal(a[1], "baz");

	arr_insert(a, 2, "bar");
	assert_int_equal(arr_len(a), 3);
	assert_string_equal(a[0], "foo");
	assert_string_equal(a[1], "baz");
	assert_string_equal(a[2], "bar");

	arr_del_swap(a, 0);
	assert_int_equal(arr_len(a), 2);
	assert_string_equal(a[0], "bar");
	assert_string_equal(a[1], "baz");

	arr_free(a);
}

static void dyn_str_arr(void **) {
	arr char **a = NULL;

	arr_add(a, strdup("foo"));
	arr_add(a, strdup("bar"));
	arr_add(a, strdup("baz"));

	strarr_free(a);
}

static void ext_arr(void **) {
	arr const char **arr1 = NULL;
	arr const char **arr2 = NULL;

	arr_add(arr1, "foo1");
	arr_add(arr1, "bar1");
	arr_add(arr1, "baz1");

	arr_add(arr2, "foo2");
	arr_add(arr2, "bar2");
	arr_add(arr2, "baz2");

	assert_int_equal(arr_len(arr1), 3);
	assert_int_equal(arr_len(arr2), 3);

	arr_extend(arr1, arr2);

	assert_int_equal(arr_len(arr1), 6);
	assert_string_equal(arr1[0], "foo1");
	assert_string_equal(arr1[1], "bar1");
	assert_string_equal(arr1[2], "baz1");
	assert_string_equal(arr1[3], "foo2");
	assert_string_equal(arr1[4], "bar2");
	assert_string_equal(arr1[5], "baz2");

	arr_free(arr1);
	arr_free(arr2);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(int_arr),
		cmocka_unit_test(str_arr),
		cmocka_unit_test(dyn_str_arr),
		cmocka_unit_test(ext_arr),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
