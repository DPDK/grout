// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br.h"
#include "dpdk.h"

#include <br_api.h>
#include <br_log.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_version.h>

#include <sched.h>

int br_rte_log_type;

int dpdk_init(struct boring_router *br) {
	int argc = 0, n = 0;
	char buf[BUFSIZ];
	char *argv[32];

#define eal_arg(arg)                                                                               \
	do {                                                                                       \
		if (argc > 0)                                                                      \
			n += snprintf(buf + n, sizeof(buf) - n, " %s", arg);                       \
		argv[argc++] = arg;                                                                \
	} while (0)

	eal_arg("br");
	eal_arg("-l");
	eal_arg("0");
	eal_arg("-a");
	eal_arg("0000:00:00.0");

	if (br->test_mode) {
		eal_arg("--no-shconf");
		eal_arg("--no-huge");
		eal_arg("-m");
		eal_arg("256");
	} else {
		eal_arg("--in-memory");
	}
	if (br->log_level >= RTE_LOG_DEBUG) {
		eal_arg("--log-level=*:debug");
	} else if (br->log_level >= RTE_LOG_INFO) {
		eal_arg("--log-level=*:info");
	} else {
		eal_arg("--log-level=*:notice");
	}

	LOG(INFO, "DPDK version: %s", rte_version());

	br_rte_log_type = rte_log_register_type_and_pick_level("br", RTE_LOG_INFO);
	if (br_rte_log_type < 0)
		return -1;

	LOG(INFO, "EAL arguments:%s", buf);

	if (rte_eal_init(argc, argv) < 0)
		return -1;

	return 0;
}

void dpdk_fini(void) {
	rte_eal_cleanup();
}
