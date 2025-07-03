// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

// Implement the systemd notify protocol without external dependencies.
int sd_notifyf(int unset_environment, const char *format, ...);
