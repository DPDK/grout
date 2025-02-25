// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_CONFIG
#define _GR_CONFIG

#include <stdbool.h>

struct gr_config {
	const char *api_sock_path;
	unsigned log_level;
	bool test_mode;
	bool poll_mode;
	bool log_syslog;
	bool log_packets;
	char **eal_extra_args;
};

extern struct gr_config gr_config;

#endif
