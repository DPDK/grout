// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR
#define _BR

#include <stdbool.h>

struct br_args {
	const char *api_sock_path;
	unsigned log_level;
	bool test_mode;
	bool poll_mode;
};

const struct br_args *br_args(void);

#endif
