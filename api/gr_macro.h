// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_MACRO
#define _GR_MACRO

#include <errno.h>

#define ARRAY_DIM(array) (sizeof(array) / sizeof(array[0]))
#define MEMBER_SIZE(type, member) (sizeof(((type *)0)->member))
#define PAYLOAD(header) ((void *)(header + 1))

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

#endif
