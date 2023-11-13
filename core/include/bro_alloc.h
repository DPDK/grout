// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BRO_ALLOC
#define _BRO_ALLOC

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static inline void *xmalloc(size_t len) {
	void *ptr = malloc(len);
	if (ptr == NULL) {
		abort();
	}
	return ptr;
}

static inline void *xcalloc(size_t num, size_t len) {
	void *ptr = calloc(num, len);
	if (ptr == NULL) {
		abort();
	}
	return ptr;
}

static inline void *xrealloc(void *ptr, size_t len) {
	ptr = realloc(ptr, len);
	if (ptr == NULL) {
		abort();
	}
	return ptr;
}

static inline char *xstrdup(const char *s) {
	char *dup = strdup(s);
	if (dup == NULL) {
		abort();
	}
	return dup;
}

static inline char *xstrndup(const char *s, size_t max_len) {
	char *dup = strndup(s, max_len);
	if (dup == NULL) {
		abort();
	}
	return dup;
}

#endif // _BRO_ALLOC
