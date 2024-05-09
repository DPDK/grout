// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_MACRO
#define _BR_MACRO

#define ARRAY_DIM(array) (sizeof(array) / sizeof(array[0]))
#define MEMBER_SIZE(type, member) (sizeof(((type *)0)->member))

#endif
