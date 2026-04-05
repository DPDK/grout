// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// convenience tag to indicate that a pointer is managed with vec_* macros
#define vec

#define __VEC_MAGIC UINT64_C(0x23061981)

// (internal) vector header
struct __vec_hdr {
#ifndef NDEBUG
	uint64_t magic;
#endif
	uint32_t len;
	uint32_t cap;
};

// (internal) get a pointer the vector header
static inline struct __vec_hdr *__vec_hdr(const void *v) {
	if (v == NULL)
		return NULL;

	struct __vec_hdr *hdr = ((struct __vec_hdr *)v) - 1;
#ifndef NDEBUG
	assert(hdr->magic == __VEC_MAGIC);
#endif
	return hdr;
}

// (internal) get the current capacity of a vector
static inline uint32_t __vec_cap(const void *v) {
	if (v == NULL)
		return 0;
	return __vec_hdr(v)->cap;
}

// get the size of a vector
static inline uint32_t vec_len(const void *v) {
	if (v == NULL)
		return 0;
	return __vec_hdr(v)->len;
}

// (internal) allocate memory to prepare for more items
__attribute__((returns_nonnull)) static inline void *
__vec_grow(void *v, size_t item_size, uint32_t add_num, uint32_t min_cap) {
	uint32_t min_len = vec_len(v) + add_num;
	struct __vec_hdr *hdr;

	if (min_len > min_cap)
		min_cap = min_len;
	if (min_cap <= __vec_cap(v))
		return v;

	// ensure large enough capacity grow to avoid multiple realloc calls
	if (min_cap < 2 * __vec_cap(v))
		min_cap = 2 * __vec_cap(v);
	else if (min_cap < 4)
		min_cap = 4;

	hdr = realloc(__vec_hdr(v), sizeof(*hdr) + item_size * min_cap);
	assert(hdr != NULL);

#ifndef NDEBUG
	hdr->magic = __VEC_MAGIC;
#endif
	if (v == NULL)
		hdr->len = 0;
	hdr->cap = min_cap;

	return hdr + 1;
}

// (internal) delete multiple items stating at a given index
static inline void __vec_del_range(void *v, size_t item_size, uint32_t start, uint32_t len) {
	struct __vec_hdr *hdr = __vec_hdr(v);
	uint32_t end = start + len;

	assert(hdr != NULL);
	assert(start < hdr->len);
	assert(len > 0);
	assert(item_size > 0);

	if (end >= hdr->len) {
		hdr->len = start;
		return;
	}

	memmove((void *)((uintptr_t)v + (item_size * start)),
		(void *)((uintptr_t)v + (item_size * end)),
		item_size * (vec_len(v) - end));

	hdr->len -= len;
}

// (internal) delete multiple items stating at a given index
__attribute__((returns_nonnull)) static inline void *
__vec_shift_range(void *v, size_t item_size, uint32_t start, uint32_t len) {
	uint32_t end = start + len;

	assert(len > 0);
	assert(item_size > 0);
	assert(start <= vec_len(v));

	v = __vec_grow(v, item_size, len, 0);

	memmove((void *)((uintptr_t)v + (item_size * end)),
		(void *)((uintptr_t)v + (item_size * start)),
		item_size * (vec_len(v) - start));

	__vec_hdr(v)->len += len;

	return v;
}

// (internal) clone a vector
static inline void *__vec_clone(const void *v, size_t item_size) {
	struct __vec_hdr *hdr;

	if (vec_len(v) == 0)
		return NULL;

	hdr = malloc(sizeof(*hdr) + (vec_len(v) * item_size));
	assert(hdr != NULL);

#ifndef NDEBUG
	hdr->magic = __VEC_MAGIC;
#endif
	hdr->len = hdr->cap = vec_len(v);
	memcpy(hdr + 1, v, vec_len(v) * item_size);

	return hdr + 1;
}

// (internal) concatenate items from ext at the end of a vector
static inline void *__vec_extend(void *v, const void *e, size_t item_size) {
	uint32_t ext_len = vec_len(e);

	if (ext_len == 0)
		return v;

	v = __vec_grow(v, item_size, ext_len, 0);
	memcpy((void *)((uintptr_t)v + (item_size * vec_len(v))), e, ext_len * item_size);
	__vec_hdr(v)->len += ext_len;

	return v;
}

// (internal) free a vector of dynamically allocated strings
static inline char **__strvec_free(vec char **v) {
	for (unsigned i = 0; i < vec_len(v); i++)
		free(v[i]);
	free(__vec_hdr(v));
	return NULL;
}

// free a previously allocated vector
#define vec_free(v) ((v) ? free(__vec_hdr(v)) : (void)0, (v) = NULL)

// free a previously allocated string vector along with all the strings
#define strvec_free(v) ((v) = __strvec_free(v))

// clone a vector into a new one
#define vec_clone(v) __vec_clone(v, sizeof(*(v)))

// force a vector with a specified min capacity
#define vec_cap_set(v, c) ((v) = __vec_grow((v), sizeof(*(v)), 0, (c)))

// ensure a vector has enough capacity to add n items
#define vec_maybe_grow(v, n) ((v) = __vec_grow((v), sizeof(*(v)), (n), 0))

// add an item at the end of a vector
#define vec_add(v, x) (vec_maybe_grow(v, 1), (v)[__vec_hdr(v)->len++] = (x))

// append all items of a vector at the end of another vector
#define vec_extend(v, v2) ((v) = __vec_extend(v, v2, sizeof(*(v))))

// add an item at a specific index in a vector
#define vec_insert(v, i, x) ((v) = __vec_shift_range(v, sizeof(*(v)), (i), 1), (v)[i] = (x))

// remove the last item from a vector and return it
#define vec_pop(v) (assert(vec_len(v) > 0), (v)[--__vec_hdr(v)->len])

// get the last item from a vector
#define vec_last(v) (assert(vec_len(v) > 0), (v)[__vec_hdr(v)->len - 1])

// delete an item at the specified index, shifting following items
#define vec_del(v, i) __vec_del_range(v, sizeof(*(v)), (i), 1)

// delete multiple items stating at a given index
#define vec_del_n(v, i, n) __vec_del_range(v, sizeof(*(v)), (i), (n))

// replace the item at the specified index with the last item
#define vec_del_swap(v, i) ((v)[i] = vec_last(v), __vec_hdr(v)->len--)

// iterate over a vector, dereferencing each item into a local variable
#define vec_foreach(x, v)                                                                          \
	for (uint32_t __i = 0, __next = 1; __next && __i < vec_len(v); __next = !__next, __i++)    \
		for (x = v[__i]; __next; __next = !__next)

// iterate over a vector, referencing each item into a local pointer
#define vec_foreach_ref(p, v)                                                                      \
	for (uint32_t __i = 0, __next = 1; __next && __i < vec_len(v); __next = !__next, __i++)    \
		for (p = &v[__i]; __next; __next = !__next)
