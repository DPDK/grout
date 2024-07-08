// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_ETH_INPUT
#define _GR_INFRA_ETH_INPUT

#include "gr_mbuf.h"

#include <gr_iface.h>

#include <rte_byteorder.h>
#include <rte_graph.h>

GR_MBUF_PRIV_DATA_TYPE(eth_input_mbuf_data, { const struct iface *iface; });

void gr_eth_input_add_type(rte_be16_t eth_type, const char *node_name);

#endif
