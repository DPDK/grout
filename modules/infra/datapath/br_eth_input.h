// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_ETH_INPUT
#define _BR_INFRA_ETH_INPUT

#include "br_mbuf.h"

#include <br_iface.h>

#include <rte_byteorder.h>
#include <rte_graph.h>

BR_MBUF_PRIV_DATA_TYPE(eth_input_mbuf_data, { const struct iface *iface; });

void br_eth_input_add_type(rte_be16_t eth_type, rte_edge_t edge);

#endif
