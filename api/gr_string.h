// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_errno.h>

#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Copy a string into a fixed-size buffer. Return -ENAMETOOLONG if src is too long.
static inline int gr_strcpy(char *dst, size_t size, const char *src) {
	if (memccpy(dst, src, 0, size) == NULL) {
		dst[size - 1] = 0;
		return errno_set(ENAMETOOLONG);
	}
	return 0;
}

// Concatenate formatted string to existing buffer (realloc as needed).
// buf is freed; caller must use returned pointer. Returns NULL on error.
char *astrcat(char *buf, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

// Join array of strings with separator.
char *strjoin(char **array, size_t len, const char *sep);

// Format CPU set as human readable string with ranges (e.g. "0,1,3-9").
int cpuset_format(char *buf, size_t len, const cpu_set_t *set);

// Parse CPU list string (e.g. "0,1,3-9") into a cpu_set_t object.
int cpuset_parse(cpu_set_t *set, const char *buf);

// Parse a string into an unsigned integer (wrapper around strtoul).
int parse_uint(unsigned *u, const char *s, unsigned base, unsigned min, unsigned max);
