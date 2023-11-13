// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BROUTER_CORE_DPDK
#define _BROUTER_CORE_DPDK

#include "bro.h"

int dpdk_init(struct brouter *);
void dpdk_fini(struct brouter *);

extern int bro_rte_log_type;
#define RTE_LOGTYPE_BRO bro_rte_log_type

#define LOG(level, fmt, ...)                                                                       \
	do {                                                                                       \
		static_assert(                                                                     \
			!__builtin_strchr(fmt, '\n'), "This log format string contains a \\n"      \
		);                                                                                 \
		RTE_LOG(level, BRO, BROUTER ": " #level ": " fmt "\n" __VA_OPT__(, ) __VA_ARGS__); \
	} while (0)

#endif // _BROUTER_CORE_DPDK
