// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_CORE_STB_DS
#define _BR_CORE_STB_DS

#include "stb_ds.h"

#define stbds_arrforeach(v, a)                                                                     \
	for (int __i = 0, __next = 1; __next && __i < arrlen(a); __next = !__next, __i++)          \
		for (v = &a[__i]; __next; __next = !__next)

// extra macros for dynamic string vectors
#define stbds_arrput_strdup(a, v) stbds_arrput(a, strdup(v))
#define stbds_arrpush_strdup stbds_arrput_strdup
#define stbds_arrpop_free(a) free(stbds_arrpop(a))
#define stbds_arrfree_all(a)                                                                       \
	do {                                                                                       \
		while (stbds_arrlen(a) > 0)                                                        \
			stbds_arrpop_free(a);                                                      \
		stbds_arrfree(a);                                                                  \
	} while (0)

// short names
#define arrput_strdup stbds_arrput_strdup
#define arrpush_strdup stbds_arrpush_strdup
#define arrpop_free stbds_arrpop_free
#define arrfree_all stbds_arrfree_all
#define arrforeach stbds_arrforeach

#endif
