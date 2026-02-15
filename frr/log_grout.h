// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <lib/zlog.h>
#include <zebra/debug.h>

#define gr_log(priority, fmt, ...) zlog(priority, "GROUT: " fmt, ##__VA_ARGS__)
#define gr_log_err(fmt, ...) gr_log(LOG_ERR, fmt, ##__VA_ARGS__)
#define gr_log_debug(fmt, ...)                                                                     \
	do {                                                                                       \
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK)                                                    \
			gr_log(LOG_DEBUG, "%s: " fmt, __func__, ##__VA_ARGS__);                    \
	} while (0)
