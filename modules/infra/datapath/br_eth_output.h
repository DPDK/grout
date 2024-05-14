// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_ETH_OUTPUT
#define _BR_INFRA_ETH_OUTPUT

#include "br_mbuf.h"

#include <rte_build_config.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include <stdint.h>

BR_MBUF_PRIV_DATA_TYPE(eth_output_mbuf_data, {
	struct rte_ether_addr dst;
	rte_be16_t ether_type;
	uint16_t iface_id;
});

#endif
