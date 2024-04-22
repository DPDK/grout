// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "worker_priv.h"

#include <br_control.h>
#include <br_infra.h>
#include <br_log.h>
#include <br_port.h>
#include <br_queue.h>
#include <br_stb_ds.h>
#include <br_worker.h>

#include <numa.h>
#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

struct ports ports;

int32_t port_create(const char *devargs) {
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct rte_dev_iterator iterator;
	struct port *port;
	int ret;

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		return -EEXIST;
	}

	if ((ret = rte_dev_probe(devargs)) < 0)
		return ret;

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		break;
	}
	if (!rte_eth_dev_is_valid_port(port_id))
		return -ENOENT;

	port = calloc(1, sizeof(*port));
	if (port == NULL) {
		port_destroy(port_id);
		return -ENOMEM;
	}

	port->port_id = port_id;
	LIST_INSERT_HEAD(&ports, port, next);

	if ((ret = port_reconfig(port)) < 0) {
		port_destroy(port_id);
		return ret;
	}

	return port_id;
}

struct port *find_port(uint16_t port_id) {
	struct port *port;
	LIST_FOREACH (port, &ports, next) {
		if (port->port_id == port_id)
			return port;
	}
	return NULL;
}

int port_destroy(uint16_t port_id) {
	struct rte_eth_dev_info info;
	struct worker *worker, *tmp;
	struct port *port;
	size_t n_workers;
	int ret;

	port = find_port(port_id);
	if (port == NULL)
		return -ENODEV;

	port_unplug(port);

	ret = rte_eth_dev_info_get(port_id, &info);
	if (ret == 0)
		ret = rte_eth_dev_stop(port_id);
	if (ret == 0)
		ret = rte_eth_dev_close(port_id);
	if (ret == 0)
		ret = rte_dev_remove(info.device);
	if (port != NULL) {
		rte_mempool_free(port->pool);
		port->pool = NULL;
		LIST_REMOVE(port, next);
		free(port);
	}
	if (ret != 0)
		return ret;

	LOG(INFO, "port %u destroyed", port_id);

	LIST_FOREACH_SAFE (worker, &workers, next, tmp) {
		for (int i = 0; i < arrlen(worker->rxqs); i++) {
			if (worker->rxqs[i].port_id == port_id) {
				arrdelswap(worker->rxqs, i);
				i--;
			}
		}
		if (arrlen(worker->rxqs) == 0)
			worker_destroy(worker->cpu_id);
	}
	n_workers = worker_count();
	if (worker_count() != n_workers) {
		LIST_FOREACH (port, &ports, next) {
			if ((ret = port_reconfig(port)) < 0)
				goto out;
		}
	}
out:
	return ret;
}

#define ETHER_FRAME_GAP 20

uint32_t port_get_rxq_buffer_us(uint16_t port_id, uint16_t rxq_id) {
	uint32_t frame_size, pkts_per_us;
	struct rte_eth_rxq_info qinfo;
	struct rte_eth_link link;
	int ret;

	if ((ret = rte_eth_link_get_nowait(port_id, &link)) < 0)
		return 0;
	switch (link.link_speed) {
	case RTE_ETH_SPEED_NUM_NONE:
	case RTE_ETH_SPEED_NUM_UNKNOWN:
		return 0;
	}

	if (rte_eth_rx_queue_info_get(port_id, rxq_id, &qinfo) < 0)
		return 0;

	// minimum ethernet frame size on the wire
	frame_size = (RTE_ETHER_MIN_LEN + ETHER_FRAME_GAP) * 8;

	// reported speed by driver is in megabit/s and we need a result in micro seconds.
	// we can use link_speed without any conversion: megabit/s is equivalent to bit/us
	pkts_per_us = link.link_speed / frame_size;
	if (pkts_per_us == 0)
		return 0;

	return qinfo.nb_desc / pkts_per_us;
}

static uint16_t get_rxq_size(struct port *p, const struct rte_eth_dev_info *info) {
	if (p->rxq_size == 0)
		p->rxq_size = info->default_rxportconf.ring_size;
	if (p->rxq_size == 0)
		p->rxq_size = RTE_ETH_DEV_FALLBACK_RX_RINGSIZE;
	return p->rxq_size;
}

static uint16_t get_txq_size(struct port *p, const struct rte_eth_dev_info *info) {
	if (p->txq_size == 0)
		p->txq_size = info->default_txportconf.ring_size;
	if (p->txq_size == 0)
		p->txq_size = RTE_ETH_DEV_FALLBACK_TX_RINGSIZE;
	return p->txq_size;
}

static struct rte_eth_conf default_port_config = {
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL, // use default key
			.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
		},
	},
	.rxmode = {
		.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
	},
};

int port_reconfig(struct port *p) {
	int socket_id = rte_eth_dev_socket_id(p->port_id);
	struct rte_eth_conf conf = default_port_config;
	struct worker *worker, *default_worker = NULL;
	uint16_t n_txq, rxq_size, txq_size;
	struct rte_eth_dev_info info;
	char pool_name[128];
	uint32_t mbuf_count;
	int ret;

	if ((ret = port_unplug(p)) < 0)
		return ret;

	// ensure there is a datapath worker running on the socket where the port is
	if ((ret = worker_ensure_default(socket_id)) < 0)
		return ret;

	// FIXME: deal with drivers that do not support more than 1 (or N) tx queues
	n_txq = worker_count();

	if ((ret = rte_eth_dev_info_get(p->port_id, &info)) < 0)
		return ret;

	if (p->n_rxq == 0)
		p->n_rxq = 1;
	rxq_size = get_rxq_size(p, &info);
	txq_size = get_txq_size(p, &info);

	if ((ret = rte_eth_dev_stop(p->port_id)) < 0) {
		LOG(ERR, "rte_eth_dev_stop: %s", rte_strerror(-ret));
		return ret;
	}

	rte_mempool_free(p->pool);
	p->pool = NULL;

	// Limit configured rss hash functions to only those supported by hardware
	conf.rx_adv_conf.rss_conf.rss_hf &= info.flow_type_rss_offloads;
	if (conf.rx_adv_conf.rss_conf.rss_hf == 0)
		conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
	else
		conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	conf.rxmode.offloads &= info.rx_offload_capa;

	if ((ret = rte_eth_dev_configure(p->port_id, p->n_rxq, n_txq, &conf)) < 0) {
		LOG(ERR, "rte_eth_dev_configure: %s", rte_strerror(-ret));
		return ret;
	}

	mbuf_count = rxq_size * p->n_rxq;
	mbuf_count += txq_size * n_txq;
	mbuf_count += RTE_GRAPH_BURST_SIZE;
	mbuf_count = rte_align32pow2(mbuf_count) - 1;
	snprintf(pool_name, sizeof(pool_name), "mbuf_%s", rte_dev_name(info.device));
	p->pool = rte_pktmbuf_pool_create(
		pool_name,
		mbuf_count,
		256, // cache_size
		0, // priv_size
		RTE_MBUF_DEFAULT_BUF_SIZE,
		socket_id
	);
	if (p->pool == NULL) {
		LOG(ERR, "rte_pktmbuf_pool_create: %s", rte_strerror(rte_errno));
		return -rte_errno;
	}

	// initialize rx/tx queues
	for (size_t q = 0; q < p->n_rxq; q++) {
		ret = rte_eth_rx_queue_setup(p->port_id, q, rxq_size, socket_id, NULL, p->pool);
		if (ret < 0) {
			LOG(ERR, "rte_eth_rx_queue_setup: %s", rte_strerror(-ret));
			return ret;
		}
	}
	for (size_t q = 0; q < n_txq; q++) {
		ret = rte_eth_tx_queue_setup(p->port_id, q, txq_size, socket_id, NULL);
		if (ret < 0) {
			LOG(ERR, "rte_eth_tx_queue_setup: %s", rte_strerror(-ret));
			return ret;
		}
	}

	// update queue/worker mapping
	uint16_t txq = 0;
	// XXX: can we assume there will never be more than 64 rxqs per port?
	uint64_t rxq_ids = 0;
	LIST_FOREACH (worker, &workers, next) {
		struct queue_map tx_qmap = {
			.port_id = p->port_id,
			.queue_id = txq,
			.enabled = false,
		};
		for (int i = 0; i < arrlen(worker->txqs); i++) {
			if (worker->txqs[i].port_id == p->port_id) {
				// ensure no duplicates
				arrdelswap(worker->txqs, i);
				i--;
			}
		}
		// assign one txq to every worker
		arrpush(worker->txqs, tx_qmap);
		txq++;

		for (int i = 0; i < arrlen(worker->rxqs); i++) {
			struct queue_map *qmap = &worker->rxqs[i];
			if (qmap->port_id == p->port_id) {
				if (qmap->queue_id < p->n_rxq) {
					// rxq already assigned to a worker
					rxq_ids |= 1 << qmap->queue_id;
				} else {
					// remove extraneous rxq
					arrdelswap(worker->rxqs, i);
					i--;
				}
			}
		}
		if (socket_id == SOCKET_ID_ANY || socket_id == numa_node_of_cpu(worker->cpu_id)) {
			default_worker = worker;
		}
	}
	assert(default_worker != NULL);
	for (uint16_t rxq = 0; rxq < p->n_rxq; rxq++) {
		if (rxq_ids & (1 << rxq))
			continue;
		struct queue_map rx_qmap = {
			.port_id = p->port_id,
			.queue_id = rxq,
			.enabled = false,
		};
		arrpush(default_worker->rxqs, rx_qmap);
	}

	if ((ret = rte_eth_dev_start(p->port_id)) < 0) {
		LOG(ERR, "rte_eth_dev_start: %s", rte_strerror(-ret));
		return ret;
	}

	return port_plug(p);
}

static void port_fini(void) {
	struct port *port, *tmp;

	LIST_FOREACH_SAFE (port, &ports, next, tmp)
		port_destroy(port->port_id);

	LIST_INIT(&ports);
}

static struct br_module port_module = {
	.name = "port",
	.fini = port_fini,
	.fini_prio = 1000,
};

RTE_INIT(port_init) {
	br_register_module(&port_module);
}
