// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CORE_DPDK
#define _BR_CORE_DPDK

#include "br.h"

int dpdk_init(struct boring_router *);
void dpdk_fini(void);

#endif
