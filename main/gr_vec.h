// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_VEC
#define _GR_VEC

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// (internal) vector header
struct __gr_vec_hdr {
	size_t len;
	size_t cap;
};

// (internal) get a pointer the vector header
static inline struct __gr_vec_hdr *__gr_vec_hdr(const void *vec) {
	if (vec == NULL)
		return NULL;
	return ((struct __gr_vec_hdr *)vec) - 1;
}

// (internal) get the current capacity of a vector
static inline size_t __gr_vec_cap(const void *vec) {
	if (vec == NULL)
		return 0;
	return __gr_vec_hdr(vec)->cap;
}

// get the size of a vector
static inline size_t gr_vec_len(const void *vec) {
	if (vec == NULL)
		return 0;
	return __gr_vec_hdr(vec)->len;
}

// (internal) allocate memory to prepare for more items
static inline void *__gr_vec_grow(void *vec, size_t item_size, size_t add_num, size_t min_cap) {
	size_t min_len = gr_vec_len(vec) + add_num;
	struct __gr_vec_hdr *hdr;

	if (min_len > min_cap)
		min_cap = min_len;
	if (min_cap <= __gr_vec_cap(vec))
		return vec;

	// ensure large enough capacity grow to avoid multiple realloc calls
	if (min_cap < 2 * __gr_vec_cap(vec))
		min_cap = 2 * __gr_vec_cap(vec);
	else if (min_cap < 4)
		min_cap = 4;

	hdr = realloc(__gr_vec_hdr(vec), sizeof(*hdr) + item_size * min_cap);
	if (hdr == NULL)
		abort();

	if (vec == NULL)
		hdr->len = 0;
	hdr->cap = min_cap;

	return hdr + 1;
}

// (internal) delete multiple items stating at a given index
static inline void __gr_vec_del_range(void *vec, size_t item_size, size_t start, size_t len) {
	struct __gr_vec_hdr *hdr = __gr_vec_hdr(vec);
	size_t end = start + len;

	if (hdr == NULL || start >= hdr->len || len == 0 || item_size == 0)
		abort();

	if (end >= hdr->len) {
		hdr->len = start;
		return;
	}

	memmove((void *)((uintptr_t)vec + (item_size * start)),
		(void *)((uintptr_t)vec + (item_size * end)),
		item_size * len);

	hdr->len -= len;
}

// (internal) delete multiple items stating at a given index
static inline void *__gr_vec_shift_range(void *vec, size_t item_size, size_t start, size_t len) {
	size_t end = start + len;

	if (len == 0 || item_size == 0 || start > gr_vec_len(vec))
		abort();

	vec = __gr_vec_grow(vec, item_size, len, 0);

	memmove((void *)((uintptr_t)vec + (item_size * end)),
		(void *)((uintptr_t)vec + (item_size * start)),
		item_size * (gr_vec_len(vec) - start));

	__gr_vec_hdr(vec)->len += len;

	return vec;
}

// (internal) clone a vector
static inline void *__gr_vec_clone(const void *vec, size_t item_size) {
	struct __gr_vec_hdr *hdr;

	if (gr_vec_len(vec) == 0)
		return NULL;

	hdr = malloc(sizeof(*hdr) + (gr_vec_len(vec) * item_size));
	if (hdr == NULL)
		abort();

	hdr->len = hdr->cap = gr_vec_len(vec);
	memcpy(hdr + 1, vec, gr_vec_len(vec) * item_size);

	return hdr + 1;
}

// free a previously allocated vector
#define gr_vec_free(v) ((v) ? free(__gr_vec_hdr(v)) : (void)0, (v) = NULL)

// clone a vector into a new one
#define gr_vec_clone(v) __gr_vec_clone(v, sizeof(*(v)))

// force a vector with a specified min capacity
#define gr_vec_cap_set(v, c) ((v) = __gr_vec_grow((v), sizeof(*(v)), 0, (c)))

// ensure a vector has enough capacity to add n items
#define gr_vec_maybe_grow(v, n) ((v) = __gr_vec_grow((v), sizeof(*(v)), (n), 0))

// add an item at the end of a vector
#define gr_vec_add(v, x) (gr_vec_maybe_grow(v, 1), (v)[__gr_vec_hdr(v)->len++] = (x))

// add an item at a specific index in a vector
#define gr_vec_insert(v, i, x) ((v) = __gr_vec_shift_range(v, sizeof(*(v)), (i), 1), (v)[i] = (x))

// remove the last item from a vector and return it
#define gr_vec_pop(v) (gr_vec_len(v) > 0 ? (void)0 : abort(), (v)[--__gr_vec_hdr(v)->len])

// get the last item from a vector
#define gr_vec_last(v) (gr_vec_len(v) > 0 ? (void)0 : abort(), (v)[__gr_vec_hdr(v)->len - 1])

// delete an item at the specified index, shifting following items
#define gr_vec_del(v, i) __gr_vec_del_range(v, sizeof(*(v)), (i), 1)

// delete multiple items stating at a given index
#define gr_vec_del_n(v, i, n) __gr_vec_del_range(vec, sizeof(*(v)), (i), (n))

// replace the item at the specified index with the last item
#define gr_vec_del_swap(v, i) ((v)[i] = gr_vec_last(v), __gr_vec_hdr(v)->len--)

// iterate over a vector, dereferencing each item into a local variable
#define gr_vec_foreach(x, v)                                                                       \
	for (size_t __i = 0, __next = 1; __next && __i < gr_vec_len(v); __next = !__next, __i++)   \
		for (x = v[__i]; __next; __next = !__next)

// iterate over a vector, referencing each item into a local pointer
#define gr_vec_foreach_ref(p, v)                                                                   \
	for (size_t __i = 0, __next = 1; __next && __i < gr_vec_len(v); __next = !__next, __i++)   \
		for (p = &v[__i]; __next; __next = !__next)

#endif
