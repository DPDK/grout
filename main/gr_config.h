// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_vec.h>

#include <sched.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

struct gr_config {
	const char *api_sock_path;
	uid_t api_sock_uid;
	gid_t api_sock_gid;
	mode_t api_sock_mode;
	unsigned log_level;
	unsigned max_mtu;
	bool test_mode;
	bool poll_mode;
	bool log_syslog;
	bool log_packets;
	gr_vec char **eal_extra_args;
	cpu_set_t control_cpus; // control plane threads allowed CPUs
	cpu_set_t datapath_cpus; // datapath threads allowed CPUs
};

extern struct gr_config gr_config;
