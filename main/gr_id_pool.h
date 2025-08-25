// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile
// Simple ID allocator built on top of DPDK’s rte_bitmap
// bit 1 ⇒ ID free
// bit 0 ⇒ ID reserved
// single writer, any number of readers

#pragma once

#include <gr_errno.h>

#include <rte_bitmap.h>
#include <rte_malloc.h>

#include <stdint.h>

struct gr_id_pool {
	uint32_t max_ids;
	uint32_t used;
	// struct rte_bitmap must be aligned on a cache line
	// it's required by rte_bitmap library.
	struct rte_bitmap bmp __rte_cache_aligned;
};

static inline struct gr_id_pool *gr_id_pool_create(const char *id_pool_name, uint32_t max_ids) {
	size_t p_size, b_size;
	struct gr_id_pool *p;

	b_size = rte_bitmap_get_memory_footprint(max_ids);
	p_size = sizeof(struct gr_id_pool) - sizeof(struct rte_bitmap) + b_size;
	p = rte_zmalloc(id_pool_name, p_size, RTE_CACHE_LINE_SIZE);
	if (!p)
		return NULL;

	if (!rte_bitmap_init_with_all_set(max_ids, (uint8_t *)&p->bmp, b_size)) {
		rte_free(p);
		return NULL;
	}

	p->max_ids = max_ids;
	p->used = 0;
	return p;
}

static inline void gr_id_pool_destroy(struct gr_id_pool *p) {
	if (!p)
		return;

	rte_free(p);
}

static inline uint32_t gr_id_pool_used(struct gr_id_pool *p) {
	return p->used;
}

static inline uint32_t gr_id_pool_avail(struct gr_id_pool *p) {
	return p->max_ids - p->used;
}

// Get the lowest‑numbered free ID; 0 if none
static inline uint32_t gr_id_pool_get(struct gr_id_pool *p) {
	uint64_t slab = 0;
	uint32_t pos = 0;
	uint32_t bit;

	__rte_bitmap_scan_init(&p->bmp);
	if (!rte_bitmap_scan(&p->bmp, &pos, &slab))
		return 0; // pool is full

	bit = pos + rte_ctz64(slab);
	rte_bitmap_clear(&p->bmp, bit); // mark used

	p->used++;
	return bit + 1;
}

// Reserve a user‑chosen ID. Returns 0 on success, <0 on error
static inline int gr_id_pool_book(struct gr_id_pool *p, uint32_t id) {
	if (id == 0 || id > p->max_ids)
		return errno_set(EINVAL);

	// already used
	if (!rte_bitmap_get(&p->bmp, id - 1))
		return errno_set(EEXIST);

	rte_bitmap_clear(&p->bmp, id - 1);
	p->used++;
	return 0;
}

// Put an ID back to the pool
static inline int gr_id_pool_put(struct gr_id_pool *p, uint32_t id) {
	if (id == 0 || id > p->max_ids)
		return errno_set(EINVAL);

	if (rte_bitmap_get(&p->bmp, id - 1))
		return errno_set(EALREADY);

	rte_bitmap_set(&p->bmp, id - 1);
	p->used--;
	return 0;
}
