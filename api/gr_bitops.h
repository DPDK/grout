// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_BITOPS
#define _GR_BITOPS

#include <stdint.h>

#define GR_BIT8(n) (UINT8_C(1) << (n))
#define GR_BIT16(n) (UINT16_C(1) << (n))
#define GR_BIT32(n) (UINT32_C(1) << (n))
#define GR_BIT64(n) (UINT64_C(1) << (n))

#endif
