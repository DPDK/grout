// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "port_config.h"
#include "worker.h"

#include <br_control.h>
#include <br_log.h>

#include <rte_bitops.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include <sys/queue.h>

static struct rte_eth_conf default_port_config = {
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL, // use default key
			.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
		},
	},
};

int port_destroy(uint16_t port_id, struct port *port) {
	struct rte_eth_dev_info info;
	int ret;

	port_unplug(port, true);

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
		rte_free(port);
	}

	return ret;
}

#define BR_MAX_BURST_SIZE 32
#define MBUF_CACHE_SIZE 256
#define qsize(info, type)

static uint16_t rx_size(struct rte_eth_dev_info *info) {
	uint16_t size = info->default_rxportconf.ring_size;
	if (size == 0) {
		size = RTE_ETH_DEV_FALLBACK_RX_RINGSIZE;
	}
	return size;
}

static uint16_t tx_size(struct rte_eth_dev_info *info) {
	uint16_t size = info->default_txportconf.ring_size;
	if (size == 0) {
		size = RTE_ETH_DEV_FALLBACK_TX_RINGSIZE;
	}
	return size;
}

int port_reconfig(struct port *p, uint16_t n_rxq) {
	struct rte_eth_conf conf = default_port_config;
	struct rte_eth_dev_info info;
	char pool_name[128];
	uint32_t mbuf_count;
	uint16_t n_txq;
	int ret;

	// FIXME: deal with drivers that do not support more than 1 (or N) tx queues
	n_txq = worker_count();
	if (n_txq == 0) {
		// no worker created yet, it will be spawned when the port is plugged
		n_txq = 1;
	}

	if ((ret = rte_eth_dev_info_get(p->port_id, &info)) < 0)
		return ret;

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

	if ((ret = rte_eth_dev_configure(p->port_id, n_rxq, n_txq, &conf)) < 0) {
		LOG(ERR, "rte_eth_dev_configure: %s", rte_strerror(-ret));
		return ret;
	}

	if ((ret = rte_eth_promiscuous_enable(p->port_id)) < 0) {
		LOG(ERR, "rte_eth_promiscuous_enable: %s", rte_strerror(-ret));
		return ret;
	}

	mbuf_count = rx_size(&info) * n_rxq;
	mbuf_count += tx_size(&info) * n_txq;
	mbuf_count += BR_MAX_BURST_SIZE;
	mbuf_count = rte_align32pow2(mbuf_count) - 1;
	snprintf(pool_name, sizeof(pool_name), "mbuf_%s", rte_dev_name(info.device));
	p->pool = rte_pktmbuf_pool_create(
		pool_name,
		mbuf_count,
		MBUF_CACHE_SIZE,
		0, // priv_size
		RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_eth_dev_socket_id(p->port_id)
	);
	if (p->pool == NULL) {
		LOG(ERR, "rte_pktmbuf_pool_create: %s", rte_strerror(rte_errno));
		return -rte_errno;
	}

	for (size_t q = 0; q < n_rxq; q++) {
		if ((ret = rte_eth_rx_queue_setup(p->port_id, q, 0, 0, NULL, p->pool)) < 0) {
			LOG(ERR, "rte_eth_rx_queue_setup: %s", rte_strerror(-ret));
			return ret;
		}
	}
	for (size_t q = 0; q < n_txq; q++) {
		if ((ret = rte_eth_tx_queue_setup(p->port_id, q, 0, 0, NULL)) < 0) {
			LOG(ERR, "rte_eth_tx_queue_setup: %s", rte_strerror(-ret));
			return ret;
		}
	}
	if ((ret = rte_eth_dev_start(p->port_id)) < 0) {
		LOG(ERR, "rte_eth_dev_start: %s", rte_strerror(-ret));
		return ret;
	}

	return 0;
}
