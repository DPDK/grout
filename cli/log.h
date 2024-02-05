// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CLI_LOG
#define _BR_CLI_LOG

#include "exec.h"

#include <stdio.h>

#define BOLD_RED_SGR "\x1b[1;31m"
#define BOLD_YELLOW_SGR "\x1b[1;33m"
#define CYAN_SGR "\x1b[36m"
#define RESET_SGR "\x1b[0m"

void tty_init(void);

bool is_tty(const FILE *);

int print_cmd_status(exec_status_t status);

void trace_cmd(const char *line);

#endif
