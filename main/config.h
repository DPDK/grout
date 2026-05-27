// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include "vec.h"

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
	// Adaptive RSS auto-scaling: dynamically narrows the per-port RSS
	// distribution + parks idle workers. The value is the cluster
	// grouping size used to keep scaling steps aligned with cache-
	// sharing groups so a step never splits one across active/parked:
	//   0   = disabled (legacy: all workers always poll all configured
	//         queues, no parking, no RETA scale).
	//   1   = enabled, per-core scaling (no cluster constraint).
	//   2   = enabled, scale by groups of 2. Typical use: x86 with
	//         hyperthreading (sibling threads share L1/L2), or any SoC
	//         where 2 cores share an L2 cache.
	//   N>2 = enabled, scale by groups of N. For larger cache-sharing
	//         topologies.
	// Set via --rss-autoscale=N at startup.
	uint16_t rss_autoscale;
	vec char **eal_extra_args;
	cpu_set_t control_cpus; // control plane threads allowed CPUs
	cpu_set_t datapath_cpus; // datapath threads allowed CPUs
	const char *metrics_addr; // openmetrics listen address (NULL to disable)
	uint16_t metrics_port; // openmetrics listen port (0 to disable)
};

extern struct gr_config gr_config;
