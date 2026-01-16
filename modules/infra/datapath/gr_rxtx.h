// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_graph.h>
#include <gr_infra.h>

#include <rte_build_config.h>
#include <rte_graph.h>
#include <rte_spinlock.h>

#include <stddef.h>
#include <stdint.h>

#define RX_NODE_BASE "port_rx"
#define RX_NODE_FMT RX_NODE_BASE "-p%uq%u"
#define TX_NODE_BASE "port_tx"
#define TX_NODE_FMT TX_NODE_BASE "-p%uq%u"

struct port_queue {
	uint16_t port_id;
	uint16_t queue_id;
};

GR_NODE_CTX_TYPE(rx_node_ctx, {
	const struct iface *iface;
	struct port_queue rxq;
	uint16_t burst_size;
});

GR_NODE_CTX_TYPE(tx_node_ctx, {
	struct port_queue txq;
	rte_spinlock_t *lock;
});

struct port_output_edges {
	rte_edge_t edges[RTE_MAX_ETHPORTS];
};

int rxtx_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/);

void iface_input_mode_register(gr_iface_mode_t, const char *next_node);
