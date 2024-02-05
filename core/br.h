// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR
#define _BR

#include <event2/event.h>

#include <sched.h>
#include <stdbool.h>

struct boring_router {
	const char *api_sock_path;
	unsigned log_level;
	bool test_mode;
	cpu_set_t cores;
};

int parse_cpu_list(const char *arg, cpu_set_t *cpuset);

#endif
