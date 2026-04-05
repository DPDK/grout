// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "_cmocka.h"
#include "vec.h"

static void int_vec(void **) {
	vec int *v = NULL;

	assert_int_equal(vec_len(v), 0);

	for (int i = 0; i < 5; i++)
		vec_add(v, i);

	assert_int_equal(vec_len(v), 5);

	for (int i = 0; i < 5; i++)
		assert_int_equal(v[i], i);

	vec_del(v, 0);
	assert_int_equal(vec_len(v), 4);
	for (int i = 0; i < 4; i++)
		assert_int_equal(v[i], i + 1);

	vec_insert(v, 0, 0);
	assert_int_equal(vec_len(v), 5);
	for (int i = 0; i < 5; i++)
		assert_int_equal(v[i], i);

	vec_insert(v, 1, 42);
	assert_int_equal(vec_len(v), 6);
	assert_int_equal(v[0], 0);
	assert_int_equal(v[1], 42);
	assert_int_equal(v[2], 1);
	assert_int_equal(v[3], 2);
	assert_int_equal(v[4], 3);
	assert_int_equal(v[5], 4);

	vec_del_swap(v, 3);
	assert_int_equal(vec_len(v), 5);

	assert_int_equal(vec_pop(v), 3);
	assert_int_equal(vec_pop(v), 4);
	assert_int_equal(vec_pop(v), 1);
	assert_int_equal(vec_pop(v), 42);

	vec_del_swap(v, 0);
	assert_int_equal(vec_len(v), 0);

	vec_free(v);
}

static void str_vec(void **) {
	vec const char **v = NULL;

	assert_int_equal(vec_len(v), 0);

	vec_add(v, "foo");
	vec_add(v, "bar");
	vec_add(v, "baz");

	assert_int_equal(vec_len(v), 3);
	assert_string_equal(v[0], "foo");
	assert_string_equal(v[1], "bar");
	assert_string_equal(v[2], "baz");

	vec_del(v, 1);

	assert_int_equal(vec_len(v), 2);
	assert_string_equal(v[0], "foo");
	assert_string_equal(v[1], "baz");

	vec_insert(v, 2, "bar");
	assert_int_equal(vec_len(v), 3);
	assert_string_equal(v[0], "foo");
	assert_string_equal(v[1], "baz");
	assert_string_equal(v[2], "bar");

	vec_del_swap(v, 0);
	assert_int_equal(vec_len(v), 2);
	assert_string_equal(v[0], "bar");
	assert_string_equal(v[1], "baz");

	vec_free(v);
}

static void dyn_str_vec(void **) {
	vec char **v = NULL;

	vec_add(v, strdup("foo"));
	vec_add(v, strdup("bar"));
	vec_add(v, strdup("baz"));

	strvec_free(v);
}

static void ext_vec(void **) {
	vec const char **vec1 = NULL;
	vec const char **vec2 = NULL;

	vec_add(vec1, "foo1");
	vec_add(vec1, "bar1");
	vec_add(vec1, "baz1");

	vec_add(vec2, "foo2");
	vec_add(vec2, "bar2");
	vec_add(vec2, "baz2");

	assert_int_equal(vec_len(vec1), 3);
	assert_int_equal(vec_len(vec2), 3);

	vec_extend(vec1, vec2);

	assert_int_equal(vec_len(vec1), 6);
	assert_string_equal(vec1[0], "foo1");
	assert_string_equal(vec1[1], "bar1");
	assert_string_equal(vec1[2], "baz1");
	assert_string_equal(vec1[3], "foo2");
	assert_string_equal(vec1[4], "bar2");
	assert_string_equal(vec1[5], "baz2");

	vec_free(vec1);
	vec_free(vec2);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(int_vec),
		cmocka_unit_test(str_vec),
		cmocka_unit_test(dyn_str_vec),
		cmocka_unit_test(ext_vec),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
