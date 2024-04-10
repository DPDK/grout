// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_BITOPS
#define _BR_BITOPS

#include <stdint.h>

#define BR_BIT16(n) (UINT16_C(1) << (n))
#define BR_BIT32(n) (UINT32_C(1) << (n))
#define BR_BIT64(n) (UINT64_C(1) << (n))

#endif
