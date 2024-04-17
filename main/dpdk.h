// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CORE_DPDK
#define _BR_CORE_DPDK

#include "br.h"

int dpdk_init(struct br_args *);
void dpdk_fini(void);

#endif
