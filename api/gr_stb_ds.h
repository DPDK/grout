// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_CORE_STB_DS
#define _GR_CORE_STB_DS

#include <stb_ds.h>

#define stbds_arrforeach(v, a)                                                                     \
	for (int __i = 0, __next = 1; __next && __i < arrlen(a); __next = !__next, __i++)          \
		for (v = &a[__i]; __next; __next = !__next)

#define arrforeach stbds_arrforeach

char *arrjoin(char **array, char *sep);

#endif
