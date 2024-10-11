// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <rte_ether.h>

#ifndef _ETH_TRACE_PRIV_H
#define _ETH_TRACE_PRIV_H

struct trace_ether_data {
	struct rte_ether_addr dst;
	struct rte_ether_addr src;
	rte_be16_t ether_type;
	uint16_t vlan_id;
	uint16_t iface_id;
};

int format_eth(void *data, char *buf, size_t len);

#endif
