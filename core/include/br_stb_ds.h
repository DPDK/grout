// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_CORE_STB_DS
#define _BR_CORE_STB_DS

#include "stb_ds.h"

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

#endif
