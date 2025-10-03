// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_cmocka.h>
#include <gr_vec.h>

int gr_rte_log_type __attribute__((weak));

static void int_vec(void **) {
	gr_vec int *vec = NULL;

	assert_int_equal(gr_vec_len(vec), 0);

	for (int i = 0; i < 5; i++)
		gr_vec_add(vec, i);

	assert_int_equal(gr_vec_len(vec), 5);

	for (int i = 0; i < 5; i++)
		assert_int_equal(vec[i], i);

	gr_vec_del(vec, 0);
	assert_int_equal(gr_vec_len(vec), 4);
	for (int i = 0; i < 4; i++)
		assert_int_equal(vec[i], i + 1);

	gr_vec_insert(vec, 0, 0);
	assert_int_equal(gr_vec_len(vec), 5);
	for (int i = 0; i < 5; i++)
		assert_int_equal(vec[i], i);

	gr_vec_insert(vec, 1, 42);
	assert_int_equal(gr_vec_len(vec), 6);
	assert_int_equal(vec[0], 0);
	assert_int_equal(vec[1], 42);
	assert_int_equal(vec[2], 1);
	assert_int_equal(vec[3], 2);
	assert_int_equal(vec[4], 3);
	assert_int_equal(vec[5], 4);

	gr_vec_del_swap(vec, 3);
	assert_int_equal(gr_vec_len(vec), 5);

	assert_int_equal(gr_vec_pop(vec), 3);
	assert_int_equal(gr_vec_pop(vec), 4);
	assert_int_equal(gr_vec_pop(vec), 1);
	assert_int_equal(gr_vec_pop(vec), 42);

	gr_vec_del_swap(vec, 0);
	assert_int_equal(gr_vec_len(vec), 0);

	gr_vec_free(vec);
}

static void str_vec(void **) {
	gr_vec const char **vec = NULL;

	assert_int_equal(gr_vec_len(vec), 0);

	gr_vec_add(vec, "foo");
	gr_vec_add(vec, "bar");
	gr_vec_add(vec, "baz");

	assert_int_equal(gr_vec_len(vec), 3);
	assert_string_equal(vec[0], "foo");
	assert_string_equal(vec[1], "bar");
	assert_string_equal(vec[2], "baz");

	gr_vec_del(vec, 1);

	assert_int_equal(gr_vec_len(vec), 2);
	assert_string_equal(vec[0], "foo");
	assert_string_equal(vec[1], "baz");

	gr_vec_insert(vec, 2, "bar");
	assert_int_equal(gr_vec_len(vec), 3);
	assert_string_equal(vec[0], "foo");
	assert_string_equal(vec[1], "baz");
	assert_string_equal(vec[2], "bar");

	gr_vec_del_swap(vec, 0);
	assert_int_equal(gr_vec_len(vec), 2);
	assert_string_equal(vec[0], "bar");
	assert_string_equal(vec[1], "baz");

	gr_vec_free(vec);
}

static void dyn_str_vec(void **) {
	gr_vec char **vec = NULL;

	gr_vec_add(vec, strdup("foo"));
	gr_vec_add(vec, strdup("bar"));
	gr_vec_add(vec, strdup("baz"));

	gr_strvec_free(vec);
}

static void ext_vec(void **) {
	gr_vec const char **vec1 = NULL;
	gr_vec const char **vec2 = NULL;

	gr_vec_add(vec1, "foo1");
	gr_vec_add(vec1, "bar1");
	gr_vec_add(vec1, "baz1");

	gr_vec_add(vec2, "foo2");
	gr_vec_add(vec2, "bar2");
	gr_vec_add(vec2, "baz2");

	assert_int_equal(gr_vec_len(vec1), 3);
	assert_int_equal(gr_vec_len(vec2), 3);

	gr_vec_extend(vec1, vec2);

	assert_int_equal(gr_vec_len(vec1), 6);
	assert_string_equal(vec1[0], "foo1");
	assert_string_equal(vec1[1], "bar1");
	assert_string_equal(vec1[2], "baz1");
	assert_string_equal(vec1[3], "foo2");
	assert_string_equal(vec1[4], "bar2");
	assert_string_equal(vec1[5], "baz2");

	gr_vec_free(vec1);
	gr_vec_free(vec2);
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
