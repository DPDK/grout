// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_SD_NOTIFY_H
#define _GR_SD_NOTIFY_H

// Implement the systemd notify protocol without external dependencies.
int sd_notifyf(int unset_environment, const char *format, ...);

#endif
