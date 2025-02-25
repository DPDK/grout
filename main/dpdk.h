// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_CORE_DPDK
#define _GR_CORE_DPDK

int dpdk_log_init(void);
int dpdk_init(void);
void dpdk_fini(void);

#endif
