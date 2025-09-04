// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_cmocka.h>
#include <gr_id_pool.h>

#include <stdlib.h>

void *__wrap_rte_malloc(const char *, size_t, unsigned);
void *__wrap_rte_malloc(const char *, size_t sz, unsigned) {
	return malloc(sz);
}

void __wrap_rte_free(void *ptr);
void __wrap_rte_free(void *ptr) {
	free(ptr);
}

static void id_sequence(void **) {
	struct gr_id_pool *p = gr_id_pool_create(1, 122);
	assert_non_null(p);
	assert_int_equal(gr_id_pool_used(p), 0);
	assert_int_equal(gr_id_pool_avail(p), 122);
	assert_int_equal(gr_id_pool_put(p, 2), -EIDRM);
	for (unsigned i = 1; i < 6; i++)
		assert_int_equal(gr_id_pool_get(p), i);
	assert_int_equal(gr_id_pool_put(p, 2), 0);
	assert_int_equal(gr_id_pool_get(p), 2);
	for (unsigned i = 6; i <= 122; i++)
		assert_int_equal(gr_id_pool_get(p), i);
	assert_int_equal(gr_id_pool_get(p), 0);
	assert_int_equal(gr_id_pool_put(p, 42), 0);
	assert_int_equal(gr_id_pool_get(p), 42);
	assert_int_equal(gr_id_pool_book(p, 666), -ERANGE);
	assert_int_equal(gr_id_pool_book(p, 0), -ERANGE);
	assert_int_equal(gr_id_pool_book(p, 42), -EADDRINUSE);
	assert_int_equal(gr_id_pool_put(p, 666), -ERANGE);
	assert_int_equal(gr_id_pool_put(p, 0), -ERANGE);
	gr_id_pool_destroy(p);
}

static void id_random(void **) {
	struct gr_id_pool *p = gr_id_pool_create(1024, 65535);
	assert_non_null(p);
	assert_int_equal(gr_id_pool_used(p), 0);
	assert_int_equal(gr_id_pool_avail(p), 64512);
	assert_int_equal(gr_id_pool_put(p, 2), -ERANGE);
	assert_int_equal(gr_id_pool_put(p, 1024), -EIDRM);
	uint32_t i1 = gr_id_pool_get_random(p);
	assert_int_equal(gr_id_pool_book(p, i1), -EADDRINUSE);
	uint32_t i2 = gr_id_pool_get_random(p);
	assert_int_equal(gr_id_pool_book(p, i2), -EADDRINUSE);
	gr_id_pool_destroy(p);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(id_sequence),
		cmocka_unit_test(id_random),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
