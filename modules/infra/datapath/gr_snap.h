// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#pragma once

#include <gr_mbuf.h>

#include <rte_byteorder.h>
#include <rte_ether.h>

#define SNAP_MAX_LEN 1536

GR_MBUF_PRIV_DATA_TYPE(eth_snap_mbuf_data, {
	struct rte_ether_addr src;
	struct rte_ether_addr dst;
	rte_be16_t len;
});

void gr_snap_input_add_mac_redirect(const struct rte_ether_addr *mac_addr, const char *next_node);

struct snap_trace_data {
	struct rte_ether_addr dst;
	struct rte_ether_addr src;
	uint16_t len;
	uint16_t iface_id;
};
int snap_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/);
