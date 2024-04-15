// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_TX
#define _BR_INFRA_TX

#include <br_mbuf.h>

#include <rte_build_config.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include <stdint.h>

BR_MBUF_PRIV_DATA_TYPE(tx_mbuf_data, {
	struct rte_ether_addr dst;
	rte_be16_t ether_type;
});

struct tx_node_queues {
	uint16_t txq_ids[RTE_MAX_ETHPORTS];
};

#endif
