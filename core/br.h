// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR
#define _BR

#include <event2/event.h>

#include <stdbool.h>

struct boring_router {
	const char *config_file_path;
	const char *api_sock_path;
	unsigned log_level;
	bool test_mode;

	// dpdk
	struct rte_mempool *api_pool; // for control API messages
};

#endif
