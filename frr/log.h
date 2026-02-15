// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <lib/zlog.h>
#include <zebra/debug.h>

extern unsigned long zg_debug;

#define ZG_DEBUG 0x01
#define ZG_IS_DEBUG (zg_debug & ZG_DEBUG)

#define zg_log(priority, fmt, ...) zlog(priority, "GROUT: " fmt, ##__VA_ARGS__)
#define zg_log_err(fmt, ...) zg_log(LOG_ERR, fmt, ##__VA_ARGS__)
#define zg_log_debug(fmt, ...)                                                                     \
	do {                                                                                       \
		if (ZG_IS_DEBUG)                                                                   \
			zg_log(LOG_DEBUG, "%s: " fmt, __func__, ##__VA_ARGS__);                    \
	} while (0)
