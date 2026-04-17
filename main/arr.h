// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// convenience tag to indicate that a pointer is managed with arr_* macros
#define arr

#define __ARR_MAGIC UINT64_C(0x23061981)

// (internal) array header
struct __arr_hdr {
#ifndef NDEBUG
	uint64_t magic;
#endif
	uint32_t len;
	uint32_t cap;
};

// (internal) get a pointer the array header
static inline struct __arr_hdr *__arr_hdr(const void *a) {
	if (a == NULL)
		return NULL;

	struct __arr_hdr *hdr = ((struct __arr_hdr *)a) - 1;
#ifndef NDEBUG
	assert(hdr->magic == __ARR_MAGIC);
#endif
	return hdr;
}

// (internal) get the current capacity of an array
static inline uint32_t __arr_cap(const void *a) {
	if (a == NULL)
		return 0;
	return __arr_hdr(a)->cap;
}

// get the size of an array
static inline uint32_t arr_len(const void *a) {
	if (a == NULL)
		return 0;
	return __arr_hdr(a)->len;
}

// (internal) allocate memory to prepare for more items
__attribute__((returns_nonnull)) static inline void *
__arr_grow(void *a, size_t item_size, uint32_t add_num, uint32_t min_cap) {
	uint32_t min_len = arr_len(a) + add_num;
	struct __arr_hdr *hdr;

	if (min_len > min_cap)
		min_cap = min_len;
	if (min_cap <= __arr_cap(a))
		return a;

	// ensure large enough capacity grow to avoid multiple realloc calls
	if (min_cap < 2 * __arr_cap(a))
		min_cap = 2 * __arr_cap(a);
	else if (min_cap < 4)
		min_cap = 4;

	hdr = realloc(__arr_hdr(a), sizeof(*hdr) + item_size * min_cap);
	assert(hdr != NULL);

#ifndef NDEBUG
	hdr->magic = __ARR_MAGIC;
#endif
	if (a == NULL)
		hdr->len = 0;
	hdr->cap = min_cap;

	return hdr + 1;
}

// (internal) delete multiple items stating at a given index
static inline void __arr_del_range(void *a, size_t item_size, uint32_t start, uint32_t len) {
	struct __arr_hdr *hdr = __arr_hdr(a);
	uint32_t end = start + len;

	assert(hdr != NULL);
	assert(start < hdr->len);
	assert(len > 0);
	assert(item_size > 0);

	if (end >= hdr->len) {
		hdr->len = start;
		return;
	}

	memmove((void *)((uintptr_t)a + (item_size * start)),
		(void *)((uintptr_t)a + (item_size * end)),
		item_size * (arr_len(a) - end));

	hdr->len -= len;
}

// (internal) delete multiple items stating at a given index
__attribute__((returns_nonnull)) static inline void *
__arr_shift_range(void *a, size_t item_size, uint32_t start, uint32_t len) {
	uint32_t end = start + len;

	assert(len > 0);
	assert(item_size > 0);
	assert(start <= arr_len(a));

	a = __arr_grow(a, item_size, len, 0);

	memmove((void *)((uintptr_t)a + (item_size * end)),
		(void *)((uintptr_t)a + (item_size * start)),
		item_size * (arr_len(a) - start));

	__arr_hdr(a)->len += len;

	return a;
}

// (internal) clone an array
static inline void *__arr_clone(const void *a, size_t item_size) {
	struct __arr_hdr *hdr;

	if (arr_len(a) == 0)
		return NULL;

	hdr = malloc(sizeof(*hdr) + (arr_len(a) * item_size));
	assert(hdr != NULL);

#ifndef NDEBUG
	hdr->magic = __ARR_MAGIC;
#endif
	hdr->len = hdr->cap = arr_len(a);
	memcpy(hdr + 1, a, arr_len(a) * item_size);

	return hdr + 1;
}

// (internal) concatenate items from ext at the end of an array
static inline void *__arr_extend(void *a, const void *e, size_t item_size) {
	uint32_t ext_len = arr_len(e);

	if (ext_len == 0)
		return a;

	a = __arr_grow(a, item_size, ext_len, 0);
	memcpy((void *)((uintptr_t)a + (item_size * arr_len(a))), e, ext_len * item_size);
	__arr_hdr(a)->len += ext_len;

	return a;
}

// (internal) free an array of dynamically allocated strings
static inline char **__strarr_free(arr char **a) {
	for (unsigned i = 0; i < arr_len(a); i++)
		free(a[i]);
	free(__arr_hdr(a));
	return NULL;
}

// free a previously allocated array
#define arr_free(a) ((a) ? free(__arr_hdr(a)) : (void)0, (a) = NULL)

// free a previously allocated string array along with all the strings
#define strarr_free(a) ((a) = __strarr_free(a))

// clone an array into a new one
#define arr_clone(a) __arr_clone(a, sizeof(*(a)))

// force an array with a specified min capacity
#define arr_cap_set(a, c) ((a) = __arr_grow((a), sizeof(*(a)), 0, (c)))

// ensure an array has enough capacity to add n items
#define arr_maybe_grow(a, n) ((a) = __arr_grow((a), sizeof(*(a)), (n), 0))

// add an item at the end of an array
#define arr_add(a, x) (arr_maybe_grow(a, 1), (a)[__arr_hdr(a)->len++] = (x))

// append all items of an array at the end of another array
#define arr_extend(a, v2) ((a) = __arr_extend(a, v2, sizeof(*(a))))

// add an item at a specific index in an array
#define arr_insert(a, i, x) ((a) = __arr_shift_range(a, sizeof(*(a)), (i), 1), (a)[i] = (x))

// remove the last item from an array and return it
#define arr_pop(a) (assert(arr_len(a) > 0), (a)[--__arr_hdr(a)->len])

// get the last item from an array
#define arr_last(a) (assert(arr_len(a) > 0), (a)[__arr_hdr(a)->len - 1])

// delete an item at the specified index, shifting following items
#define arr_del(a, i) __arr_del_range(a, sizeof(*(a)), (i), 1)

// delete multiple items stating at a given index
#define arr_del_n(a, i, n) __arr_del_range(a, sizeof(*(a)), (i), (n))

// replace the item at the specified index with the last item
#define arr_del_swap(a, i) ((a)[i] = arr_last(a), __arr_hdr(a)->len--)

// iterate over an array, dereferencing each item into a local variable
#define arr_foreach(x, a)                                                                          \
	for (uint32_t __i = 0, __next = 1; __next && __i < arr_len(a); __next = !__next, __i++)    \
		for (x = a[__i]; __next; __next = !__next)

// iterate over an array, referencing each item into a local pointer
#define arr_foreach_ref(p, a)                                                                      \
	for (uint32_t __i = 0, __next = 1; __next && __i < arr_len(a); __next = !__next, __i++)    \
		for (p = &a[__i]; __next; __next = !__next)
