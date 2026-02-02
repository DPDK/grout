// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_control_queue.h>
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

void iface_output_type_register(gr_iface_type_t, const char *next_node);

void iface_cp_tx(void *obj, uintptr_t priv, const struct control_queue_drain *);

#define IFACE_STATS_VARS(dir)                                                                      \
	struct iface_stats *dir##_stats;                                                           \
	uint16_t dir##_last_iface_id = GR_IFACE_ID_UNDEF;                                          \
	uint16_t dir##_packets = 0;                                                                \
	uint64_t dir##_bytes = 0;

#define IFACE_STATS_INC(dir, mbuf, iface)                                                          \
	do {                                                                                       \
		if (iface->id != dir##_last_iface_id) {                                            \
			if (dir##_packets != 0) {                                                  \
				dir##_stats = iface_get_stats(                                     \
					rte_lcore_id(), dir##_last_iface_id                        \
				);                                                                 \
				dir##_stats->dir##_packets += dir##_packets;                       \
				dir##_stats->dir##_bytes += dir##_bytes;                           \
				dir##_packets = 0;                                                 \
				dir##_bytes = 0;                                                   \
			}                                                                          \
			dir##_last_iface_id = iface->id;                                           \
		}                                                                                  \
		dir##_packets += 1;                                                                \
		dir##_bytes += rte_pktmbuf_pkt_len(mbuf);                                          \
	} while (0)

#define IFACE_STATS_FLUSH(dir)                                                                     \
	do {                                                                                       \
		if (dir##_packets != 0) {                                                          \
			dir##_stats = iface_get_stats(rte_lcore_id(), dir##_last_iface_id);        \
			dir##_stats->dir##_packets += dir##_packets;                               \
			dir##_stats->dir##_bytes += dir##_bytes;                                   \
		}                                                                                  \
	} while (0)
