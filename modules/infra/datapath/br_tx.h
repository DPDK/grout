// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_TX
#define _BR_INFRA_TX

#include <rte_build_config.h>

#include <stdint.h>

struct tx_node_queues {
	uint16_t txq_ids[RTE_MAX_ETHPORTS];
};

#endif
