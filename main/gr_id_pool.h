// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile
// Simple ID allocator built on top of DPDK’s rte_bitmap
// bit 1 ⇒ ID free
// bit 0 ⇒ ID reserved
// single writer, any number of readers

#pragma once

#include <gr_bitops.h>
#include <gr_errno.h>

#include <rte_malloc.h>
#include <rte_random.h>

#include <stdatomic.h>
#include <stdint.h>
#include <strings.h>

struct gr_id_pool {
	uint32_t min_id;
	uint32_t max_id;
	atomic_uint_fast32_t used;
	uint32_t slabs_len;
	atomic_uint_fast64_t slabs[];
};

#define GR_ID_POOL_SLAB_MASK UINT64_C(0xffffffffffffffff)
#define GR_ID_POOL_SLAB_SIZE 64

static inline struct gr_id_pool *gr_id_pool_create(uint32_t min_id, uint32_t max_id) {
	uint32_t slabs_len, range, tail;
	struct gr_id_pool *p;

	if (min_id == 0 || min_id >= max_id)
		return errno_set_null(ERANGE);

	range = max_id - min_id + 1;
	slabs_len = range / GR_ID_POOL_SLAB_SIZE;
	tail = range % GR_ID_POOL_SLAB_SIZE;
	if (tail != 0)
		slabs_len += 1;

	p = rte_malloc(
		__func__, sizeof(*p) + (slabs_len * sizeof(p->slabs[0])), RTE_CACHE_LINE_SIZE
	);
	if (p == NULL)
		return errno_set_null(ENOMEM);

	p->min_id = min_id;
	p->max_id = max_id;
	p->used = 0;
	p->slabs_len = slabs_len;
	// Mark all IDs available (0 means reserved).
	memset(p->slabs, 0xff, slabs_len * sizeof(p->slabs[0]));
	if (tail != 0) {
		// If the number of IDs isn't a multiple of 64, the last word of the array will be
		// "incomplete". Mark the last bits as reserved so that they are never used.
		p->slabs[slabs_len - 1] = GR_ID_POOL_SLAB_MASK >> (GR_ID_POOL_SLAB_SIZE - tail);
	}

	return p;
}

static inline void gr_id_pool_destroy(struct gr_id_pool *p) {
	if (!p)
		return;

	rte_free(p);
}

static inline uint32_t gr_id_pool_used(struct gr_id_pool *p) {
	return atomic_load(&p->used);
}

static inline uint32_t gr_id_pool_avail(struct gr_id_pool *p) {
	return p->max_id - p->min_id + 1 - atomic_load(&p->used);
}

// Get the lowest‑numbered free ID; 0 if none
static inline uint32_t gr_id_pool_get(struct gr_id_pool *p) {
	uint64_t new_slab, old_slab;
	uint32_t bit;

	// Iterate over all slabs starting from the first one.
	for (uint32_t s = 0; s < p->slabs_len; s++) {
again:
		// Get the first "available" bit from this slab.
		old_slab = atomic_load(&p->slabs[s]);
		bit = ffsll(old_slab);
		if (bit == 0)
			continue; // Current slab is full. Go to next one.

		// ffsll() returns values starting at 1 for bit 0. Convert it to real bit offset.
		bit--;
		// Clear the bit (1 means available, 0 means reserved)
		new_slab = old_slab & ~GR_BIT64(bit);

		if (atomic_compare_exchange_strong(&p->slabs[s], &old_slab, new_slab)) {
			// Slab successfully updated, return the actual ID value.
			atomic_fetch_add(&p->used, 1);
			return p->min_id + (s * GR_ID_POOL_SLAB_SIZE) + bit;
		}

		// Atomic CAS failed (another thread modified it before us).
		// Try again with the next "available" bit in the same slab.
		goto again;
	}

	// Pool entirely full.
	return 0;
}

// Get the a random free ID; 0 if none are available
static inline uint32_t gr_id_pool_get_random(struct gr_id_pool *p) {
	uint64_t new_slab, old_slab;
	uint32_t bit, slot;

	// Grab a random starting slot.
	slot = rte_rand() % p->slabs_len;

	// Ensure we only inspect each slab once.
	for (uint32_t s = 0; s < p->slabs_len; s++) {
again:
		// Get the first "available" bit from this slab.
		old_slab = atomic_load(&p->slabs[slot]);
		bit = ffsll(old_slab);
		if (bit == 0) {
			// Current slab is full.
			// Go to previous one, wrapping to the last one if necessary.
			slot = slot > 0 ? slot - 1 : p->slabs_len - 1;
			continue;
		}

		// ffsll() returns values starting at 1 for bit 0. Convert it to real bit offset.
		bit--;
		// Clear the bit (1 means available, 0 means reserved)
		new_slab = old_slab & ~GR_BIT64(bit);

		if (atomic_compare_exchange_strong(&p->slabs[slot], &old_slab, new_slab)) {
			// Slab successfully updated, return the actual ID value.
			atomic_fetch_add(&p->used, 1);
			return p->min_id + (slot * GR_ID_POOL_SLAB_SIZE) + bit;
		}

		// Atomic CAS failed (another thread modified it before us).
		// Try again with the next "available" bit in the same slab.
		goto again;
	}

	// Pool entirely full.
	return 0;
}

// Reserve a user‑chosen ID. Returns 0 on success, <0 on error
static inline int gr_id_pool_book(struct gr_id_pool *p, uint32_t id) {
	uint64_t new_slab, old_slab;
	uint32_t bit, offset, slot;

	if (id < p->min_id || id > p->max_id)
		return errno_set(ERANGE);

	offset = id - p->min_id;
	slot = offset / GR_ID_POOL_SLAB_SIZE;
	bit = offset % GR_ID_POOL_SLAB_SIZE;

again:
	old_slab = atomic_load(&p->slabs[slot]);
	if (!(old_slab & GR_BIT64(bit)))
		return errno_set(EADDRINUSE); // ID already reserved

	// Clear the bit (1 means available, 0 means reserved)
	new_slab = old_slab & ~GR_BIT64(bit);
	if (!atomic_compare_exchange_strong(&p->slabs[slot], &old_slab, new_slab)) {
		// Atomic CAS failed (another thread modified it before us).
		// Try again until we succeed or fail because someone else booked the same ID.
		goto again;
	}

	atomic_fetch_add(&p->used, 1);

	return 0;
}

// Put an ID back to the pool
static inline int gr_id_pool_put(struct gr_id_pool *p, uint32_t id) {
	uint64_t new_slab, old_slab;
	uint32_t bit, offset, slot;

	if (id < p->min_id || id > p->max_id)
		return errno_set(ERANGE);

	offset = id - p->min_id;
	slot = offset / GR_ID_POOL_SLAB_SIZE;
	bit = offset % GR_ID_POOL_SLAB_SIZE;

again:
	old_slab = atomic_load(&p->slabs[slot]);
	if (old_slab & GR_BIT64(bit))
		return errno_set(EIDRM); // ID already "freed"

	// Set the bit to 1 (1 means available, 0 means reserved)
	new_slab = old_slab | GR_BIT64(bit);
	if (!atomic_compare_exchange_strong(&p->slabs[slot], &old_slab, new_slab)) {
		// Atomic CAS failed (another thread modified it before us).
		// Try again until we succeed or fail because someone else freed the same ID.
		goto again;
	}

	atomic_fetch_sub(&p->used, 1);

	return 0;
}
