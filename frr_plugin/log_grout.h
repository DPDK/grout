// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#ifndef _LOG_GROUT_H
#define _LOG_GROUT_H

#include <lib/zlog.h>
#include <zebra/debug.h>

extern unsigned long zebra_debug_dplane_grout;

#define ZEBRA_DEBUG_DPLANE_GROUT 0x01
#define IS_ZEBRA_DEBUG_DPLANE_GROUT (zebra_debug_dplane_grout & ZEBRA_DEBUG_DPLANE_GROUT)

#define gr_log(priority, fmt, ...) zlog(priority, "GROUT: " fmt, ##__VA_ARGS__)
#define gr_log_err(fmt, ...) gr_log(LOG_ERR, fmt, ##__VA_ARGS__)
#define gr_log_debug(fmt, ...)                                                                     \
	do {                                                                                       \
		if (IS_ZEBRA_DEBUG_DPLANE_GROUT)                                                   \
			gr_log(LOG_DEBUG, "%s: " fmt, __func__, ##__VA_ARGS__);                    \
	} while (0)

#endif /* _LOG_GROUT_H */
