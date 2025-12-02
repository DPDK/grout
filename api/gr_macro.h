// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <errno.h>
#include <limits.h>

// Get number of elements in a static array.
#define ARRAY_DIM(array) (sizeof(array) / sizeof(array[0]))

// Get size of a specific member in a struct type.
#define MEMBER_SIZE(type, member) (sizeof(((type *)0)->member))

// Get pointer to payload data immediately following a header.
#define PAYLOAD(header) ((void *)(header + 1))

// Get maximum number of values for an unsigned integer type (up to 32-bit).
#define UINT_NUM_VALUES(type) (1ULL << (sizeof(type) * CHAR_BIT))

// Define a structure as a base for another one using anonymous tagged structure extension.
#define BASE(typename)                                                                             \
	union {                                                                                    \
		struct typename base;                                                              \
		struct typename;                                                                   \
	}

// Call a function writing on a buffer called 'buf'.
//
// The offset at which to write is expected to be named 'n'.
//
// The function is expected to return a positive integer holding the number of
// bytes written or a negative value on error. If a negative value is returned,
// the macro will goto an 'err' label.
//
// On success, 'n' is incremented with the number of bytes written.
#define SAFE_BUF(func, buf_size, ...)                                                              \
	do {                                                                                       \
		int __s = func(buf + n, buf_size - n, __VA_ARGS__);                                \
		if (__s < 0)                                                                       \
			goto err;                                                                  \
		if (__s >= (int)(buf_size - n)) {                                                  \
			errno = ENOBUFS;                                                           \
			goto err;                                                                  \
		}                                                                                  \
		n += __s;                                                                          \
	} while (0)

#define GR_SYMBOL_FORBIDDEN(func, new_func)                                                        \
	sorry_##func##_is_a_banned_function_use_##new_func##_instead
