// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <ecoli.h>

#include <stdio.h>

#define BOLD_RED_SGR "\x1b[1;31m"
#define BOLD_YELLOW_SGR "\x1b[1;33m"
#define YELLOW_SGR "\x1b[33m"
#define CYAN_SGR "\x1b[36m"
#define RESET_SGR "\x1b[0m"

void tty_init(void);

bool is_tty(const FILE *);

const char *need_quote(const char *arg);

void trace_cmd(const struct ec_strvec *cmd);
