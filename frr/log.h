// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <lib/zlog.h>
#include <zebra/debug.h>

#define zg_log(priority, fmt, ...) zlog(priority, "GROUT: " fmt, ##__VA_ARGS__)
#define zg_log_err(fmt, ...) zg_log(LOG_ERR, "%s: " fmt, __func__, ##__VA_ARGS__)
#define zg_log_notice(fmt, ...) zg_log(LOG_NOTICE, "%s: " fmt, __func__, ##__VA_ARGS__)
#define zg_log_info(fmt, ...) zg_log(LOG_INFO, "%s: " fmt, __func__, ##__VA_ARGS__)
#define zg_log_debug(fmt, ...)                                                                     \
	do {                                                                                       \
		if (IS_ZEBRA_DEBUG_DPLANE)                                                         \
			zg_log(LOG_DEBUG, "%s: " fmt, __func__, ##__VA_ARGS__);                    \
	} while (0)
