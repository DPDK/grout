// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <gr_config.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_rxtx.h>
#include <gr_trace.h>
#include <gr_worker.h>

#include <rte_build_config.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>

#include <stdint.h>

enum {
	TX_ERROR = 0,
	TX_DOWN,
	NO_HEADROOM,
	NB_EDGES,
};

static inline bool tx_begin(
	const struct tx_node_ctx *ctx,
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface_info_port *port;
	const struct iface *iface;

	iface = mbuf_data(objs[0])->iface;
	port = iface_info_port(iface);

	if (!port->started) {
		for (unsigned i = 0; i < nb_objs; i++) {
			if (gr_mbuf_is_traced(objs[i])) {
				struct port_queue *t;
				t = gr_mbuf_trace_add(objs[i], node, sizeof(*t));
				*t = ctx->txq;
			}
		}
		rte_node_enqueue(graph, node, TX_DOWN, objs, nb_objs);
		return false;
	}

	if (unlikely(gr_config.log_packets)) {
		for (unsigned i = 0; i < nb_objs; i++) {
			struct rte_mbuf *m = objs[i];
			const struct iface *iface = mbuf_data(m)->iface;
			trace_log_packet(m, "tx", iface->name);
		}
	}

	return true;
}

static inline void tx_finish(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs,
	uint16_t tx_ok,
	rxtx_flags_t flags
) {
	if (tx_ok < nb_objs)
		rte_node_enqueue(graph, node, TX_ERROR, &objs[tx_ok], nb_objs - tx_ok);

	for (unsigned i = 0; i < tx_ok; i++) {
		// FIXME racy: we are operating on mbufs already passed to driver
		if (gr_mbuf_is_traced(objs[i])) {
			rxtx_flags_t *t = gr_mbuf_trace_add(objs[i], node, sizeof(*t));
			*t = flags;
			gr_mbuf_trace_finish(objs[i]);
		}
	}
}

static inline uint16_t tx_add_vlan(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs,
	struct rte_mbuf **mbufs
) {
	const struct iface_mbuf_data *d;
	struct rte_ether_hdr *eth;
	struct rte_vlan_hdr *vlan;
	struct rte_mbuf *m;
	uint16_t ok = 0;
	void *data;

	for (unsigned i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = iface_mbuf_data(m);
		if (d->vlan_id != 0) {
			eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			data = gr_mbuf_prepend(m, vlan);
			if (data == NULL) {
				rte_node_enqueue_x1(graph, node, NO_HEADROOM, m);
				continue;
			}
			memmove(data, eth, sizeof(*eth) - sizeof(eth->ether_type));
			eth = data;
			vlan = PAYLOAD(eth);
			vlan->vlan_tci = rte_cpu_to_be_16(d->vlan_id);
			eth->ether_type = RTE_BE16(RTE_ETHER_TYPE_VLAN);
		}
		mbufs[ok++] = m;
	}

	return ok;
}

static inline void tx_offload_add_vlan(void **objs, uint16_t nb_objs) {
	const struct iface_mbuf_data *d;
	struct rte_mbuf *m;

	for (unsigned i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = iface_mbuf_data(m);
		if (d->vlan_id != 0) {
			m->ol_flags |= RTE_MBUF_F_TX_VLAN;
			m->vlan_tci = d->vlan_id;
		}
	}
}

uint16_t tx_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct tx_node_ctx *ctx = tx_node_ctx(node);
	struct rte_mbuf *mbufs[RTE_GRAPH_BURST_SIZE];
	uint16_t tx_ok;

	if (unlikely(!tx_begin(ctx, graph, node, objs, nb_objs)))
		return 0;

	nb_objs = tx_add_vlan(graph, node, objs, nb_objs, mbufs);
	if (unlikely(nb_objs == 0))
		return 0;

	tx_ok = rte_eth_tx_burst(ctx->txq.port_id, ctx->txq.queue_id, mbufs, nb_objs);

	tx_finish(graph, node, (void *)mbufs, nb_objs, tx_ok, 0);

	return nb_objs;
}

uint16_t
tx_shared_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct tx_node_ctx *ctx = tx_node_ctx(node);
	struct rte_mbuf *mbufs[RTE_GRAPH_BURST_SIZE];
	uint16_t tx_ok;

	if (unlikely(!tx_begin(ctx, graph, node, objs, nb_objs)))
		return 0;

	nb_objs = tx_add_vlan(graph, node, objs, nb_objs, mbufs);
	if (unlikely(nb_objs == 0))
		return 0;

	rte_spinlock_lock(ctx->lock);
	tx_ok = rte_eth_tx_burst(ctx->txq.port_id, ctx->txq.queue_id, mbufs, nb_objs);
	rte_spinlock_unlock(ctx->lock);

	tx_finish(graph, node, (void *)mbufs, nb_objs, tx_ok, RXTX_F_TXQ_SHARED);

	return nb_objs;
}

uint16_t tx_shared_offload_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct tx_node_ctx *ctx = tx_node_ctx(node);
	uint16_t tx_ok;

	if (unlikely(!tx_begin(ctx, graph, node, objs, nb_objs)))
		return 0;

	tx_offload_add_vlan(objs, nb_objs);

	rte_spinlock_lock(ctx->lock);
	tx_ok = rte_eth_tx_burst(
		ctx->txq.port_id, ctx->txq.queue_id, (struct rte_mbuf **)objs, nb_objs
	);
	rte_spinlock_unlock(ctx->lock);

	tx_finish(graph, node, objs, nb_objs, tx_ok, RXTX_F_TXQ_SHARED | RXTX_F_VLAN_OFFLOAD);

	return nb_objs;
}

uint16_t
tx_offload_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	const struct tx_node_ctx *ctx = tx_node_ctx(node);
	uint16_t tx_ok;

	if (unlikely(!tx_begin(ctx, graph, node, objs, nb_objs)))
		return 0;

	tx_offload_add_vlan(objs, nb_objs);

	tx_ok = rte_eth_tx_burst(
		ctx->txq.port_id, ctx->txq.queue_id, (struct rte_mbuf **)objs, nb_objs
	);

	tx_finish(graph, node, objs, nb_objs, tx_ok, RXTX_F_VLAN_OFFLOAD);

	return nb_objs;
}

static struct rte_node_register node = {
	.name = TX_NODE_BASE,

	.process = tx_process,

	.nb_edges = NB_EDGES,
	.next_nodes = {
		[TX_ERROR] = "port_tx_error",
		[TX_DOWN] = "port_tx_down",
		[NO_HEADROOM] = "error_no_headroom",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L1,
	.trace_format = rxtx_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(port_tx_error);
GR_DROP_REGISTER(port_tx_down);
