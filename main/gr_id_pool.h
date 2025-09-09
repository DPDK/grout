// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile
// Copyright (c) 2025 Robin Jarry
//
// Simple ID allocator using atomic operations.
// bit 1 ⇒ ID free
// bit 0 ⇒ ID reserved
// multiple writers, multiple readers, thread safe, no locking

#pragma once

#include <gr_bitops.h>
#include <gr_errno.h>

#include <rte_bitops.h>
#include <rte_malloc.h>
#include <rte_random.h>

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

struct gr_id_pool {
	uint32_t min_id;
	uint32_t max_id;
	_Atomic(uint32_t) used;
	uint16_t level0_len;
	uint16_t level1_len;
	_Atomic(uint64_t) *level0;
	_Atomic(uint64_t) level1[];
} __rte_cache_aligned;

#define __ID_POOL_SLAB_SIZE UINT64_C(64)

static inline struct gr_id_pool *gr_id_pool_create(uint32_t min_id, uint32_t max_id) {
	uint16_t level1_len, level1_tail, level0_len, level0_tail;
	struct gr_id_pool *p;
	uint32_t range;

	if (min_id == 0 || min_id > max_id)
		return errno_set_null(ERANGE);

	range = max_id - min_id + 1;
	if (range / __ID_POOL_SLAB_SIZE > UINT16_MAX)
		return errno_set_null(ERANGE);

	level1_len = range / __ID_POOL_SLAB_SIZE;
	level1_tail = range % __ID_POOL_SLAB_SIZE;
	if (level1_tail != 0)
		level1_len += 1;

	level0_len = level1_len / __ID_POOL_SLAB_SIZE;
	level0_tail = level1_len % __ID_POOL_SLAB_SIZE;
	if (level0_tail != 0)
		level0_len += 1;

	p = rte_malloc(
		__func__,
		sizeof(*p) + ((level1_len + level0_len) * sizeof(p->level1[0])),
		RTE_CACHE_LINE_SIZE
	);
	if (p == NULL)
		return errno_set_null(ENOMEM);

	p->min_id = min_id;
	p->max_id = max_id;
	p->used = 0;
	p->level1_len = level1_len;
	p->level0_len = level0_len;
	// level 0 array is placed at the end of level 1
	p->level0 = &p->level1[level1_len];

	// Mark all IDs available (0 means reserved).
	memset(p->level1, 0xff, (level1_len + level0_len) * sizeof(p->level1[0]));

	// If the number of IDs isn't a multiple of 64, the last word of the array will be
	// "incomplete". Mark the last bits as reserved so that they are never used.
	if (level0_tail != 0)
		p->level0[level0_len - 1] = UINT64_MAX >> (__ID_POOL_SLAB_SIZE - level0_tail);
	if (level1_tail != 0)
		p->level1[level1_len - 1] = UINT64_MAX >> (__ID_POOL_SLAB_SIZE - level1_tail);

	return p;
}

static inline void gr_id_pool_destroy(struct gr_id_pool *p) {
	rte_free(p);
}

static inline uint32_t gr_id_pool_used(struct gr_id_pool *p) {
	return atomic_load_explicit(&p->used, memory_order_relaxed);
}

static inline uint32_t gr_id_pool_avail(struct gr_id_pool *p) {
	return p->max_id - p->min_id + 1 - atomic_load_explicit(&p->used, memory_order_relaxed);
}

// Get the lowest‑numbered free ID; 0 if none
static inline uint32_t gr_id_pool_get(struct gr_id_pool *p) {
	uint64_t level0, new_level1, old_level1;
	uint16_t level0_bit, level1_bit, l1;

	// Iterate over all level0 slabs starting from the first one.
	for (uint16_t l0 = 0; l0 < p->level0_len; l0++) {
level0:
		level0 = atomic_load_explicit(&p->level0[l0], memory_order_acquire);
		if (level0 == 0)
			continue; // Current level0 slab is full. Go to next one.

		// Get the first "available" level1 from this level0.
		level0_bit = rte_ctz64(level0);
		l1 = (l0 * __ID_POOL_SLAB_SIZE) + level0_bit;
level1:
		old_level1 = atomic_load_explicit(&p->level1[l1], memory_order_acquire);
		if (old_level1 == 0) {
			// Level1 slab is full. Another thread reserved the last ID after we read
			// level0. Find another slab from the same level0.
			goto level0;
		}

		// Get the first "available" bit from this level1 slab.
		level1_bit = rte_ctz64(old_level1);
		// Clear the bit (1 means available, 0 means reserved)
		new_level1 = old_level1 & ~GR_BIT64(level1_bit);

		if (atomic_compare_exchange_weak(&p->level1[l1], &old_level1, new_level1)) {
			if (new_level1 == 0) {
				// The level1 slab where we reserved the ID is full.
				// Clear the corresponding bit in the current level0 slab.
				//
				// XXX: very unlikely race: if 63 other threads free bits here
				// before we have a chance to clear the level0 bit, there is
				// a chance that this level1 slab becomes permanently unavailable.
				// There is no way to fix this without a spinlock.
				atomic_fetch_and_explicit(
					&p->level0[l0], ~GR_BIT64(level0_bit), memory_order_release
				);
			}
			atomic_fetch_add_explicit(&p->used, 1, memory_order_relaxed);
			// Slab successfully updated, return the actual ID value.
			return p->min_id + (l1 * __ID_POOL_SLAB_SIZE) + level1_bit;
		}

		// Atomic CAS failed (another thread modified it before us).
		// Try again with the same slab in level1.
		goto level1;
	}

	// Pool entirely full.
	return 0;
}

// Get the a random free ID; 0 if none are available
static inline uint32_t gr_id_pool_get_random(struct gr_id_pool *p) {
	uint64_t level0, new_level1, old_level1, rand;
	uint16_t level0_bit, level1_bit, l0, l1;

	// Grab a random starting level0 slab.
	rand = rte_rand();
	l0 = rand % p->level0_len;
	// Use another random bit offset to be checked first in level1 to increase entropy.
	rand = (rand >> 32) % __ID_POOL_SLAB_SIZE;

	// Ensure we only inspect each level1 slab at most once.
	for (uint16_t _ = 0; _ < p->level0_len; _++) {
level0:
		level0 = atomic_load_explicit(&p->level0[l0], memory_order_acquire);
		if (level0 == 0) {
			// Current level0 slab is full.
			// Go to previous one, wrapping to the last one if necessary.
			l0 = l0 > 0 ? l0 - 1 : p->level0_len - 1;
			continue;
		}

		if (level0 & GR_BIT64(rand)) {
			// If possible, select a random slab in this level0 to increase entropy.
			level0_bit = rand;
		} else {
			// Otherwise, use the first "available" one.
			level0_bit = rte_ctz64(level0);
		}
		l1 = (l0 * __ID_POOL_SLAB_SIZE) + level0_bit;
level1:
		old_level1 = atomic_load_explicit(&p->level1[l1], memory_order_acquire);
		if (old_level1 == 0) {
			// Level1 slab is full. Another thread reserved the last ID after we read
			// level0. Find another slab from the same level0.
			goto level0;
		}

		if (old_level1 & GR_BIT64(rand)) {
			// If possible, select a random bit in this level1 to increase entropy.
			level1_bit = rand;
		} else {
			// Otherwise, use the first "available" one.
			level1_bit = rte_ctz64(old_level1);
		}
		// Clear the bit (1 means available, 0 means reserved)
		new_level1 = old_level1 & ~GR_BIT64(level1_bit);

		if (atomic_compare_exchange_weak(&p->level1[l1], &old_level1, new_level1)) {
			if (new_level1 == 0) {
				// The level1 slab where we reserved the ID is full.
				// Clear the corresponding bit in the current level0 slab.
				//
				// XXX: very unlikely race: if 63 other threads free bits here
				// before we have a chance to clear the level0 bit, there is
				// a chance that this level1 slab becomes permanently unavailable.
				// There is no way to fix this without a spinlock.
				atomic_fetch_and_explicit(
					&p->level0[l0], ~GR_BIT64(level0_bit), memory_order_release
				);
			}
			atomic_fetch_add_explicit(&p->used, 1, memory_order_relaxed);
			// Slab successfully updated, return the actual ID value.
			return p->min_id + (l1 * __ID_POOL_SLAB_SIZE) + level1_bit;
		}

		// Atomic CAS failed (another thread modified it before us).
		// Try again with the same slab in level1.
		goto level1;
	}

	// Pool entirely full.
	return 0;
}

// Reserve a user‑chosen ID. Returns 0 on success, <0 on error
static inline int gr_id_pool_book(struct gr_id_pool *p, uint32_t id) {
	uint16_t level1_bit, l1, offset;
	uint64_t old_level1;

	if (id < p->min_id || id > p->max_id)
		return errno_set(ERANGE);

	offset = id - p->min_id;
	l1 = offset / __ID_POOL_SLAB_SIZE;
	level1_bit = offset % __ID_POOL_SLAB_SIZE;

	// Clear the bit (1 means available, 0 means reserved)
	old_level1 = atomic_fetch_and_explicit(
		&p->level1[l1], ~GR_BIT64(level1_bit), memory_order_acq_rel
	);
	if (!(old_level1 & GR_BIT64(level1_bit)))
		return errno_set(EADDRINUSE); // ID was already reserved

	if ((old_level1 & ~GR_BIT64(level1_bit)) == 0) {
		uint16_t l0 = l1 / __ID_POOL_SLAB_SIZE;
		uint16_t level0_bit = l1 % __ID_POOL_SLAB_SIZE;
		// The level1 slab where we reserved the ID is full.
		// Clear the corresponding bit in the relevant level0.
		//
		// XXX: very unlikely race: if 63 other threads free bits here
		// before we have a chance to clear the level0 bit, there is
		// a chance that this level1 slab becomes permanently unavailable.
		// There is no way to fix this without a spinlock.
		atomic_fetch_and_explicit(
			&p->level0[l0], ~GR_BIT64(level0_bit), memory_order_acq_rel
		);
	}
	atomic_fetch_add_explicit(&p->used, 1, memory_order_relaxed);

	return 0;
}

// Put an ID back to the pool
static inline int gr_id_pool_put(struct gr_id_pool *p, uint32_t id) {
	uint16_t level0_bit, level1_bit, l0, l1, offset;
	uint64_t old_level1;

	if (id < p->min_id || id > p->max_id)
		return errno_set(ERANGE);

	offset = id - p->min_id;
	l1 = offset / __ID_POOL_SLAB_SIZE;
	level1_bit = offset % __ID_POOL_SLAB_SIZE;

	old_level1 = atomic_fetch_or_explicit(
		&p->level1[l1], GR_BIT64(level1_bit), memory_order_acq_rel
	);
	if (old_level1 & GR_BIT64(level1_bit))
		return errno_set(EIDRM); // ID was already "freed"

	l0 = l1 / __ID_POOL_SLAB_SIZE;
	level0_bit = l1 % __ID_POOL_SLAB_SIZE;
	// The level1 slab where we returned the ID now contains at least one bit.
	// Set the corresponding bit in the relevant level0 slab.
	atomic_fetch_or_explicit(&p->level0[l0], GR_BIT64(level0_bit), memory_order_acq_rel);

	atomic_fetch_sub_explicit(&p->used, 1, memory_order_relaxed);

	return 0;
}
