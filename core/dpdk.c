// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br.h"
#include "dpdk.h"

#include <br_api.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_mempool.h>

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
	eal_arg("--no-shconf");
	eal_arg("-a");
	eal_arg("0000:00:00.0");
	eal_arg("--log-level=*:debug");

	if (br->test_mode) {
		eal_arg("--no-huge");
		eal_arg("-m");
		eal_arg("256");
	} else {
		eal_arg("--in-memory");
	}

	br_rte_log_type = rte_log_register_type_and_pick_level("br", RTE_LOG_INFO);
	if (br_rte_log_type < 0)
		return -1;

	LOG(INFO, "EAL arguments:%s", buf);

	if (rte_eal_init(argc, argv) < 0)
		return -1;

	br->api_pool = rte_mempool_create(
		"api",
		128, // n elements
		BR_API_MAX_MSG_LEN, // elt_size
		0, // cache_size
		0, // private_data_size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		SOCKET_ID_ANY,
		RTE_MEMPOOL_F_NO_CACHE_ALIGN | RTE_MEMPOOL_F_SP_PUT | RTE_MEMPOOL_F_SC_GET |
			RTE_MEMPOOL_F_NO_IOVA_CONTIG
	);
	if (br->api_pool == NULL) {
		LOG(ERR, "rte_mempool_create: %s", rte_strerror(rte_errno));
		return -1;
	}

	return 0;
}

void dpdk_fini(struct boring_router *br) {
	if (br->api_pool != NULL)
		rte_mempool_free(br->api_pool);
	rte_eal_cleanup();
}
