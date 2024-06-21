// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_ETH_OUTPUT
#define _GR_INFRA_ETH_OUTPUT

#include "gr_mbuf.h"

#include <gr_iface.h>

#include <rte_build_config.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include <stdint.h>

GR_MBUF_PRIV_DATA_TYPE(eth_output_mbuf_data, {
	const struct iface *iface;
	struct rte_ether_addr dst;
	rte_be16_t ether_type;
});

#endif
