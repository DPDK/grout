// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR
#define _GR

#include <stdbool.h>

struct gr_args {
	const char *api_sock_path;
	unsigned log_level;
	bool test_mode;
	bool poll_mode;
	bool log_syslog;
	char **eal_extra_args;
};

const struct gr_args *gr_args(void);

#endif
