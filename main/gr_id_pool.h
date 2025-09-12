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
	uint16_t blocks_len;
	uint16_t slabs_len;
	_Atomic(uint64_t) *blocks;
	_Atomic(uint64_t) slabs[];
} __rte_cache_aligned;

#define __ID_POOL_SLAB_SIZE UINT64_C(64)

static inline struct gr_id_pool *gr_id_pool_create(uint32_t min_id, uint32_t max_id) {
	uint16_t slabs_len, slabs_tail, blocks_len, blocks_tail;
	struct gr_id_pool *p;
	uint32_t range;

	if (min_id == 0 || min_id > max_id)
		return errno_set_null(ERANGE);

	range = max_id - min_id + 1;
	if (range / __ID_POOL_SLAB_SIZE > UINT16_MAX)
		return errno_set_null(ERANGE);

	slabs_len = range / __ID_POOL_SLAB_SIZE;
	slabs_tail = range % __ID_POOL_SLAB_SIZE;
	if (slabs_tail != 0)
		slabs_len += 1;

	blocks_len = slabs_len / __ID_POOL_SLAB_SIZE;
	blocks_tail = slabs_len % __ID_POOL_SLAB_SIZE;
	if (blocks_tail != 0)
		blocks_len += 1;

	p = rte_malloc(
		__func__,
		sizeof(*p) + ((slabs_len + blocks_len) * sizeof(p->slabs[0])),
		RTE_CACHE_LINE_SIZE
	);
	if (p == NULL)
		return errno_set_null(ENOMEM);

	p->min_id = min_id;
	p->max_id = max_id;
	p->used = 0;
	p->slabs_len = slabs_len;
	p->blocks_len = blocks_len;
	p->blocks = &p->slabs[slabs_len];

	// Mark all IDs available (0 means reserved).
	memset(p->slabs, 0xff, (slabs_len + blocks_len) * sizeof(p->slabs[0]));

	// If the number of IDs isn't a multiple of 64, the last word of the array will be
	// "incomplete". Mark the last bits as reserved so that they are never used.
	if (slabs_tail != 0) {
		p->slabs[slabs_len - 1] = UINT64_MAX >> (__ID_POOL_SLAB_SIZE - slabs_tail);
	}
	if (blocks_tail != 0) {
		p->blocks[blocks_len - 1] = UINT64_MAX >> (__ID_POOL_SLAB_SIZE - blocks_tail);
	}

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
	uint64_t block, new_slab, old_slab;
	uint16_t block_bit, slab_bit, s;

	// Iterate over all blocks starting from the first one.
	for (uint16_t b = 0; b < p->blocks_len; b++) {
again:
		block = atomic_load_explicit(&p->blocks[b], memory_order_acquire);
		if (block == 0)
			continue; // Current block is full. Go to next one.

		// Get the first "available" slab from this block.
		block_bit = rte_ctz64(block);
		s = (b * __ID_POOL_SLAB_SIZE) + block_bit;
		old_slab = atomic_load_explicit(&p->slabs[s], memory_order_acquire);
		if (old_slab == 0)
			goto again; // Slab is full. Find another slab of the same block.

		// Get the first "available" bit from this slab.
		slab_bit = rte_ctz64(old_slab);
		// Clear the bit (1 means available, 0 means reserved)
		new_slab = old_slab & ~GR_BIT64(slab_bit);

		if (atomic_compare_exchange_weak(&p->slabs[s], &old_slab, new_slab)) {
			if (new_slab == 0) {
				// The slab where we reserved the ID is full.
				// Clear the corresponding bit in the current block.
				atomic_fetch_and_explicit(
					&p->blocks[b], ~GR_BIT64(block_bit), memory_order_release
				);
			}
			atomic_fetch_add_explicit(&p->used, 1, memory_order_relaxed);
			// Slab successfully updated, return the actual ID value.
			return p->min_id + (s * __ID_POOL_SLAB_SIZE) + slab_bit;
		}

		// Atomic CAS failed (another thread modified it before us).
		// Try again with another slab of the same block.
		goto again;
	}

	// Pool entirely full.
	return 0;
}

// Get the a random free ID; 0 if none are available
static inline uint32_t gr_id_pool_get_random(struct gr_id_pool *p) {
	uint64_t block, new_slab, old_slab, rand;
	uint16_t block_bit, slab_bit, b, s;

	// Grab a random starting block.
	rand = rte_rand();
	b = rand % p->blocks_len;
	// Use another random bit offset to be checked first in slabs to increase entropy.
	rand = (rand >> 32) % __ID_POOL_SLAB_SIZE;

	// Ensure we only inspect each slab at most once.
	for (uint16_t _b = 0; _b < p->blocks_len; _b++) {
again:
		block = atomic_load_explicit(&p->blocks[b], memory_order_acquire);
		if (block == 0) {
			// Current block is full.
			// Go to previous one, wrapping to the last one if necessary.
			b = b > 0 ? b - 1 : p->blocks_len - 1;
			continue;
		}

		if (block & GR_BIT64(rand)) {
			// If available select a random slab in this block.
			block_bit = rand;
		} else {
			// Get the first "available" slab from this block.
			block_bit = rte_ctz64(block);
		}
		s = (b * __ID_POOL_SLAB_SIZE) + block_bit;
		old_slab = atomic_load_explicit(&p->slabs[s], memory_order_acquire);
		if (old_slab == 0)
			goto again; // Slab is full. Find another slab of the same block.

		// Get the first "available" bit from this slab.
		slab_bit = rte_ctz64(old_slab);
		// Clear the bit (1 means available, 0 means reserved)
		new_slab = old_slab & ~GR_BIT64(slab_bit);

		if (atomic_compare_exchange_weak(&p->slabs[s], &old_slab, new_slab)) {
			if (new_slab == 0) {
				// The slab where we reserved the ID is full.
				// Clear the corresponding bit in the current block.
				atomic_fetch_and_explicit(
					&p->blocks[b], ~GR_BIT64(block_bit), memory_order_release
				);
			}
			atomic_fetch_add_explicit(&p->used, 1, memory_order_relaxed);
			// Slab successfully updated, return the actual ID value.
			return p->min_id + (s * __ID_POOL_SLAB_SIZE) + slab_bit;
		}

		// Atomic CAS failed (another thread modified it before us).
		// Try again with the next "available" slab in the same block.
		goto again;
	}

	// Pool entirely full.
	return 0;
}

// Reserve a user‑chosen ID. Returns 0 on success, <0 on error
static inline int gr_id_pool_book(struct gr_id_pool *p, uint32_t id) {
	uint16_t slab_bit, s, offset;
	uint64_t new_slab, old_slab;

	if (id < p->min_id || id > p->max_id)
		return errno_set(ERANGE);

	offset = id - p->min_id;
	s = offset / __ID_POOL_SLAB_SIZE;
	slab_bit = offset % __ID_POOL_SLAB_SIZE;

again:
	old_slab = atomic_load_explicit(&p->slabs[s], memory_order_acquire);
	if (!(old_slab & GR_BIT64(slab_bit)))
		return errno_set(EADDRINUSE); // ID already reserved

	// Clear the bit (1 means available, 0 means reserved)
	new_slab = old_slab & ~GR_BIT64(slab_bit);

	if (!atomic_compare_exchange_weak(&p->slabs[s], &old_slab, new_slab)) {
		// Atomic CAS failed (another thread modified it before us).
		// Try again until we succeed or fail because someone else booked the same ID.
		goto again;
	}

	if (new_slab == 0) {
		uint16_t b = s / __ID_POOL_SLAB_SIZE;
		uint16_t block_bit = s % __ID_POOL_SLAB_SIZE;
		// The slab where we reserved the ID is full.
		// Clear the corresponding bit in the relevant block.
		atomic_fetch_and_explicit(
			&p->blocks[b], ~GR_BIT64(block_bit), memory_order_release
		);
	}
	atomic_fetch_add_explicit(&p->used, 1, memory_order_relaxed);

	return 0;
}

// Put an ID back to the pool
static inline int gr_id_pool_put(struct gr_id_pool *p, uint32_t id) {
	uint16_t block_bit, slab_bit, b, s, offset;
	uint64_t new_slab, old_slab;

	if (id < p->min_id || id > p->max_id)
		return errno_set(ERANGE);

	offset = id - p->min_id;
	s = offset / __ID_POOL_SLAB_SIZE;
	slab_bit = offset % __ID_POOL_SLAB_SIZE;

again:
	old_slab = atomic_load_explicit(&p->slabs[s], memory_order_acquire);
	if (old_slab & GR_BIT64(slab_bit))
		return errno_set(EIDRM); // ID already "freed"

	// Set the bit to 1 (1 means available, 0 means reserved)
	new_slab = old_slab | GR_BIT64(slab_bit);
	if (!atomic_compare_exchange_weak(&p->slabs[s], &old_slab, new_slab)) {
		// Atomic CAS failed (another thread modified it before us).
		// Try again until we succeed or fail because someone else freed the same ID.
		goto again;
	}

	b = s / __ID_POOL_SLAB_SIZE;
	block_bit = s % __ID_POOL_SLAB_SIZE;
	// The slab where we returned the ID now contains at least one bit.
	// Set the corresponding bit in the relevant block.
	atomic_fetch_or_explicit(&p->blocks[b], GR_BIT64(block_bit), memory_order_release);

	atomic_fetch_sub_explicit(&p->used, 1, memory_order_relaxed);

	return 0;
}
