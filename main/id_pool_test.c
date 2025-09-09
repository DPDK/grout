// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_cmocka.h>
#include <gr_id_pool.h>
#include <gr_macro.h>

#include <rte_cycles.h>

#include <pthread.h>
#include <stdatomic.h>
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
	assert_return_code(gr_id_pool_put(p, 2), errno);
	assert_int_equal(gr_id_pool_get(p), 2);
	for (unsigned i = 6; i <= 122; i++)
		assert_int_equal(gr_id_pool_get(p), i);
	assert_int_equal(gr_id_pool_get(p), 0);
	assert_return_code(gr_id_pool_put(p, 42), errno);
	assert_int_equal(gr_id_pool_get(p), 42);
	assert_int_equal(gr_id_pool_book(p, 666), -ERANGE);
	assert_int_equal(gr_id_pool_book(p, 0), -ERANGE);
	assert_int_equal(gr_id_pool_book(p, 42), -EADDRINUSE);
	assert_int_equal(gr_id_pool_put(p, 666), -ERANGE);
	assert_int_equal(gr_id_pool_put(p, 0), -ERANGE);
	gr_id_pool_destroy(p);

	p = gr_id_pool_create(666, 1);
	assert_null(p);
	assert_int_equal(errno, ERANGE);

	p = gr_id_pool_create(1, UINT32_MAX);
	assert_null(p);
	assert_int_equal(errno, ERANGE);
}

#define THREADS 8
#define LOOPS 10000

struct id_pool_bench {
	struct gr_id_pool *pool;
	_Atomic(int) ret;
	_Atomic(uint64_t) get;
	_Atomic(uint64_t) put;
};

static void *id_sequence_thread(void *arg) {
	struct id_pool_bench *bench = arg;
	uint64_t tsc;
	int ret;

	for (unsigned i = 0; i < LOOPS; i++) {
		tsc = rte_rdtsc();
		ret = gr_id_pool_get(bench->pool);
		atomic_fetch_add(&bench->get, rte_rdtsc() - tsc);
		if (ret == 0) {
			atomic_store(&bench->ret, -ENOSPC);
			break;
		}
		tsc = rte_rdtsc();
		ret = gr_id_pool_put(bench->pool, ret);
		atomic_fetch_add(&bench->put, rte_rdtsc() - tsc);
		if (ret < 0) {
			atomic_store(&bench->ret, ret);
			break;
		}
	}

	return NULL;
}

static void bench_summary(const char *func, const char *fill, struct id_pool_bench *bench) {
	print_message(
		"gr_id_pool_%s(%s): threads=%u iterations=%u cycles/it=%lu\n",
		func,
		fill,
		THREADS,
		LOOPS,
		bench->get / (THREADS * LOOPS)
	);
	print_message(
		"gr_id_pool_put(%s): threads=%u iterations=%u cycles/it=%lu\n",
		fill,
		THREADS,
		LOOPS,
		bench->put / (THREADS * LOOPS)
	);
}

static void id_sequence_bench(void **) {
	struct id_pool_bench bench = {
		.pool = gr_id_pool_create(1024, 65535),
	};
	assert_non_null(bench.pool);
	pthread_t threads[THREADS];
	unsigned t, id;

	bench.ret = bench.get = bench.put = 0;
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_create(&threads[t], NULL, id_sequence_thread, &bench);
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_join(threads[t], NULL);
	assert_return_code(bench.ret, -bench.ret);
	bench_summary("get", "empty", &bench);

	// reserve half of the ids
	for (id = bench.pool->min_id; id < bench.pool->max_id / 2; id++)
		assert_return_code(gr_id_pool_book(bench.pool, id), errno);

	bench.ret = bench.get = bench.put = 0;
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_create(&threads[t], NULL, id_sequence_thread, &bench);
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_join(threads[t], NULL);
	assert_return_code(bench.ret, -bench.ret);
	bench_summary("get", "half", &bench);

	// reserve all ids but the last THREADS ones
	for (id = bench.pool->max_id / 2; id <= bench.pool->max_id - THREADS; id++)
		assert_return_code(gr_id_pool_book(bench.pool, id), errno);

	bench.ret = bench.get = bench.put = 0;
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_create(&threads[t], NULL, id_sequence_thread, &bench);
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_join(threads[t], NULL);
	assert_return_code(bench.ret, -bench.ret);
	bench_summary("get", "full-1", &bench);

	gr_id_pool_destroy(bench.pool);
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

static void *id_random_thread(void *arg) {
	struct id_pool_bench *bench = arg;
	uint64_t tsc;
	int ret;

	for (unsigned i = 0; i < LOOPS; i++) {
		tsc = rte_rdtsc();
		ret = gr_id_pool_get_random(bench->pool);
		atomic_fetch_add(&bench->get, rte_rdtsc() - tsc);
		if (ret == 0) {
			atomic_store(&bench->ret, -ENOSPC);
			break;
		}
		tsc = rte_rdtsc();
		ret = gr_id_pool_put(bench->pool, ret);
		atomic_fetch_add(&bench->put, rte_rdtsc() - tsc);
		if (ret < 0) {
			atomic_store(&bench->ret, ret);
			break;
		}
	}

	return NULL;
}

static void id_random_bench(void **) {
	struct id_pool_bench bench = {
		.pool = gr_id_pool_create(1024, 65535),
	};
	assert_non_null(bench.pool);
	pthread_t threads[THREADS];
	unsigned t, id;

	bench.ret = bench.get = bench.put = 0;
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_create(&threads[t], NULL, id_random_thread, &bench);
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_join(threads[t], NULL);
	assert_return_code(bench.ret, -bench.ret);
	bench_summary("get_random", "empty", &bench);

	// reserve half of the ids
	for (id = bench.pool->min_id; id < bench.pool->max_id / 2; id++)
		assert_return_code(gr_id_pool_book(bench.pool, id), errno);

	bench.ret = bench.get = bench.put = 0;
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_create(&threads[t], NULL, id_random_thread, &bench);
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_join(threads[t], NULL);
	assert_return_code(bench.ret, -bench.ret);
	bench_summary("get_random", "half", &bench);

	// reserve all ids but the last THREAD ones
	for (id = bench.pool->max_id / 2; id <= bench.pool->max_id - THREADS; id++)
		assert_return_code(gr_id_pool_book(bench.pool, id), errno);

	bench.ret = bench.get = bench.put = 0;
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_create(&threads[t], NULL, id_random_thread, &bench);
	for (t = 0; t < ARRAY_DIM(threads); t++)
		pthread_join(threads[t], NULL);
	assert_return_code(bench.ret, -bench.ret);
	bench_summary("get_random", "full-1", &bench);

	gr_id_pool_destroy(bench.pool);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(id_sequence),
		cmocka_unit_test(id_sequence_bench),
		cmocka_unit_test(id_random),
		cmocka_unit_test(id_random_bench),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
