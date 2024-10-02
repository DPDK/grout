// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "worker_priv.h"

#include <gr.h>
#include <gr_control.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_mempool.h>
#include <gr_port.h>
#include <gr_queue.h>
#include <gr_stb_ds.h>
#include <gr_worker.h>

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

#define ETHER_FRAME_GAP 20

static int queue_buffer_us(uint32_t link_speed, uint16_t queue_size) {
	uint32_t frame_size, pkts_per_us;

	// minimum ethernet frame size on the wire
	frame_size = (RTE_ETHER_MIN_LEN + ETHER_FRAME_GAP) * 8;

	// reported speed by driver is in megabit/s and we need a result in micro seconds.
	// we can use link_speed without any conversion: megabit/s is equivalent to bit/us
	pkts_per_us = link_speed / frame_size;
	if (pkts_per_us == 0)
		return 0;

	return queue_size / pkts_per_us;
}

static uint16_t get_rxq_size(struct iface_info_port *p, const struct rte_eth_dev_info *info) {
	if (p->rxq_size == 0)
		p->rxq_size = info->default_rxportconf.ring_size;
	if (p->rxq_size == 0)
		p->rxq_size = RTE_ETH_DEV_FALLBACK_RX_RINGSIZE;
	return p->rxq_size;
}

static uint16_t get_txq_size(struct iface_info_port *p, const struct rte_eth_dev_info *info) {
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
			.rss_hf = RTE_ETH_RSS_VLAN
				| RTE_ETH_RSS_IP
				| RTE_ETH_RSS_UDP
				| RTE_ETH_RSS_TCP,
		},
	},
	.rxmode = {
		.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_VLAN,
	},
};

static void port_queue_assign(struct iface_info_port *p) {
	int socket_id = rte_eth_dev_socket_id(p->port_id);
	struct worker *worker, *default_worker = NULL;
	// XXX: can we assume there will never be more than 64 rxqs per port?
	uint64_t rxq_ids = 0;
	uint16_t txq = 0;

	STAILQ_FOREACH (worker, &workers, next) {
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
}

static int port_configure(struct iface_info_port *p) {
	int socket_id = rte_eth_dev_socket_id(p->port_id);
	struct rte_eth_conf conf = default_port_config;
	uint16_t rxq_size, txq_size;
	struct rte_eth_dev_info info;
	uint32_t mbuf_count;
	int ret;

	// ensure there is a datapath worker running on the socket where the port is
	if ((ret = worker_ensure_default(socket_id)) < 0)
		return ret;

	// FIXME: deal with drivers that do not support more than 1 (or N) tx queues
	p->n_txq = worker_count();
	if (p->n_rxq == 0)
		p->n_rxq = 1;

	if ((ret = rte_eth_dev_info_get(p->port_id, &info)) < 0)
		return errno_log(-ret, "rte_eth_dev_info_get");

	rxq_size = get_rxq_size(p, &info);
	txq_size = get_txq_size(p, &info);

	mbuf_count = rxq_size * p->n_rxq;
	mbuf_count += txq_size * p->n_txq;
	mbuf_count += RTE_GRAPH_BURST_SIZE;
	mbuf_count = rte_align32pow2(mbuf_count) - 1;
	if (mbuf_count != p->pool_size) {
		gr_pktmbuf_pool_release(p->pool, p->pool_size);
		p->pool = gr_pktmbuf_pool_get(socket_id, mbuf_count);
		p->pool_size = mbuf_count;
	}

	if (p->pool == NULL)
		return errno_log(errno, "gr_pktmbuf_pool_get");

	// Limit configured rss hash functions to only those supported by hardware
	conf.rx_adv_conf.rss_conf.rss_hf &= info.flow_type_rss_offloads;
	if (conf.rx_adv_conf.rss_conf.rss_hf == 0)
		conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
	else
		conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	conf.rxmode.offloads &= info.rx_offload_capa;
	if (info.dev_flags != NULL && *info.dev_flags & RTE_ETH_DEV_INTR_LSC) {
		conf.intr_conf.lsc = 1;
	}

	if ((ret = rte_eth_dev_configure(p->port_id, p->n_rxq, p->n_txq, &conf)) < 0)
		return errno_log(-ret, "rte_eth_dev_configure");

	// initialize rx/tx queues
	for (size_t q = 0; q < p->n_rxq; q++) {
		ret = rte_eth_rx_queue_setup(p->port_id, q, rxq_size, socket_id, NULL, p->pool);
		if (ret < 0)
			return errno_log(-ret, "rte_eth_rx_queue_setup");
	}
	for (size_t q = 0; q < p->n_txq; q++) {
		ret = rte_eth_tx_queue_setup(p->port_id, q, txq_size, socket_id, NULL);
		if (ret < 0)
			return errno_log(-ret, "rte_eth_tx_queue_setup");
	}

	port_queue_assign(p);

	p->configured = true;

	return 0;
}

int iface_port_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	uint16_t flags,
	uint16_t mtu,
	uint16_t vrf_id,
	const void *api_info
) {
	struct iface_info_port *p = (struct iface_info_port *)iface->info;
	const struct gr_iface_info_port *api = api_info;
	bool stopped = false;
	int ret;

	if ((ret = port_unplug(p->port_id)) < 0)
		return ret;

	if (set_attrs & (GR_PORT_SET_N_RXQS | GR_PORT_SET_N_TXQS | GR_PORT_SET_Q_SIZE)) {
		if (set_attrs & GR_PORT_SET_N_RXQS)
			p->n_rxq = api->n_rxq;
		if (set_attrs & GR_PORT_SET_N_TXQS)
			p->n_txq = api->n_txq;
		if (set_attrs & GR_PORT_SET_Q_SIZE) {
			p->rxq_size = api->rxq_size;
			p->txq_size = api->rxq_size;
		}
		p->configured = false;
	}

	if (!p->configured
	    || (set_attrs & (GR_IFACE_SET_FLAGS | GR_IFACE_SET_MTU | GR_PORT_SET_MAC))) {
		if ((ret = rte_eth_dev_stop(p->port_id)) < 0)
			return errno_log(-ret, "rte_eth_dev_stop");
		stopped = true;
	}
	if (!p->configured && (ret = port_configure(p)) < 0)
		return ret;

	if (set_attrs & GR_IFACE_SET_FLAGS) {
		if (flags & GR_IFACE_F_PROMISC)
			ret = rte_eth_promiscuous_enable(p->port_id);
		else
			ret = rte_eth_promiscuous_disable(p->port_id);
		if (ret < 0)
			errno_log(-ret, "rte_eth_promiscuous_{en,dis}able");
		if (rte_eth_promiscuous_get(p->port_id) == 1)
			iface->flags |= GR_IFACE_F_PROMISC;
		else
			iface->flags &= ~GR_IFACE_F_PROMISC;

		if (flags & GR_IFACE_F_ALLMULTI)
			ret = rte_eth_allmulticast_enable(p->port_id);
		else
			ret = rte_eth_allmulticast_disable(p->port_id);
		if (ret < 0)
			errno_log(-ret, "rte_eth_allmulticast_{en,dis}able");
		if (rte_eth_allmulticast_get(p->port_id) == 1)
			iface->flags |= GR_IFACE_F_ALLMULTI;
		else
			iface->flags &= ~GR_IFACE_F_ALLMULTI;

		if (flags & GR_IFACE_F_UP) {
			ret = rte_eth_dev_set_link_up(p->port_id);
			iface->flags |= GR_IFACE_F_UP;
		} else {
			ret = rte_eth_dev_set_link_down(p->port_id);
			iface->flags &= ~GR_IFACE_F_UP;
		}
		if (ret < 0)
			errno_log(-ret, "rte_eth_dev_set_link_{up,down}");
	}

	if ((set_attrs & GR_IFACE_SET_MTU) && mtu != 0) {
		if ((ret = rte_eth_dev_set_mtu(p->port_id, mtu)) < 0)
			return errno_log(-ret, "rte_eth_dev_set_mtu");
		iface->mtu = mtu;
	} else {
		if ((ret = rte_eth_dev_get_mtu(p->port_id, &iface->mtu)) < 0)
			return errno_log(-ret, "rte_eth_dev_get_mtu");
	}

	if (set_attrs & GR_IFACE_SET_VRF)
		iface->vrf_id = vrf_id;

	if ((set_attrs & GR_PORT_SET_MAC) && !rte_is_zero_ether_addr(&api->mac)) {
		struct rte_ether_addr mac = api->mac;
		if ((ret = rte_eth_dev_default_mac_addr_set(p->port_id, &mac)) < 0)
			return errno_log(-ret, "rte_eth_dev_default_mac_addr_set");
		p->mac = mac;
	} else {
		if ((ret = rte_eth_macaddr_get(p->port_id, &p->mac)) < 0)
			return errno_log(-ret, "rte_eth_macaddr_get");
	}

	if (stopped && (ret = rte_eth_dev_start(p->port_id)) < 0)
		return errno_log(-ret, "rte_eth_dev_start");

	iface_event_notify(IFACE_EVENT_PORT_POST_RECONFIG, iface);

	return port_plug(p->port_id);
}

static const struct iface *port_ifaces[RTE_MAX_ETHPORTS];

static int iface_port_fini(struct iface *iface) {
	struct iface_info_port *port = (struct iface_info_port *)iface->info;
	struct rte_eth_dev_info info;
	struct worker *worker, *tmp;
	size_t n_workers;
	int ret;

	port_unplug(port->port_id);

	port_ifaces[port->port_id] = NULL;

	free(port->devargs);
	port->devargs = NULL;
	if ((ret = rte_eth_dev_info_get(port->port_id, &info)) < 0)
		LOG(ERR, "rte_eth_dev_info_get: %s", rte_strerror(-ret));
	if ((ret = rte_eth_dev_stop(port->port_id)) < 0)
		LOG(ERR, "rte_eth_dev_stop: %s", rte_strerror(-ret));
	if ((ret = rte_eth_dev_close(port->port_id)) < 0)
		LOG(ERR, "rte_eth_dev_close: %s", rte_strerror(-ret));
	if (info.device != NULL && (ret = rte_dev_remove(info.device)) < 0)
		LOG(ERR, "rte_dev_remove: %s", rte_strerror(-ret));
	if (port->pool != NULL) {
		gr_pktmbuf_pool_release(port->pool, port->pool_size);
		port->pool = NULL;
	}

	LOG(INFO, "port %u destroyed", port->port_id);

	n_workers = worker_count();
	STAILQ_FOREACH_SAFE (worker, &workers, next, tmp) {
		for (int i = 0; i < arrlen(worker->rxqs); i++) {
			if (worker->rxqs[i].port_id == port->port_id) {
				arrdelswap(worker->rxqs, i);
				i--;
			}
		}
		if (arrlen(worker->rxqs) == 0)
			worker_destroy(worker->cpu_id);
	}
	if (worker_count() != n_workers) {
		// update the number of tx queues for all ports
		struct iface *iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
			struct iface_info_port p = {.n_txq = 0};
			ret = iface_port_reconfig(
				iface,
				GR_PORT_SET_N_TXQS,
				iface->flags,
				iface->mtu,
				iface->vrf_id,
				&p
			);
			if (ret < 0)
				goto out;
		}
	}
out:
	return ret;
}

static int iface_port_init(struct iface *iface, const void *api_info) {
	struct iface_info_port *port = (struct iface_info_port *)iface->info;
	const struct gr_iface_info_port *api = api_info;
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct rte_dev_iterator iterator;
	int ret;

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, api->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		return errno_set(EEXIST);
	}

	if ((ret = rte_dev_probe(api->devargs)) < 0)
		return errno_set(-ret);

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, api->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		break;
	}
	if (!rte_eth_dev_is_valid_port(port_id))
		return errno_set(EIDRM);

	port->port_id = port_id;
	port->devargs = strndup(api->devargs, GR_PORT_DEVARGS_SIZE);
	if (port->devargs == NULL) {
		ret = errno_set(ENOMEM);
		goto fail;
	}

	ret = iface_port_reconfig(
		iface, IFACE_SET_ALL, iface->flags, iface->mtu, iface->vrf_id, api_info
	);
	if (ret < 0) {
		iface_port_fini(iface);
		errno = -ret;
		goto fail;
	}
	port_ifaces[port_id] = iface;

	return 0;
fail:
	free(port->devargs);
	return ret;
}

const struct iface *port_get_iface(uint16_t port_id) {
	return port_ifaces[port_id];
}

static int port_mac_get(const struct iface *iface, struct rte_ether_addr *mac) {
	struct iface_info_port *port = (struct iface_info_port *)iface->info;
	*mac = port->mac;
	return 0;
}

static int port_mac_add(struct iface *iface, const struct rte_ether_addr *mac) {
	struct iface_info_port *port = (struct iface_info_port *)iface->info;
	struct mac_filter *filter;
	const char *mac_type;
	bool multicast;
	uint8_t i;
	int ret;

	if (mac == NULL || !(rte_is_multicast_ether_addr(mac) || rte_is_unicast_ether_addr(mac)))
		return errno_set(EINVAL);

	if (rte_is_same_ether_addr(mac, &port->mac))
		return 0;

	multicast = rte_is_multicast_ether_addr(mac);
	if (multicast) {
		mac_type = "multicast";
		filter = &port->mcast_filter;
	} else {
		mac_type = "unicast";
		filter = &port->ucast_filter;
	}

	for (i = 0; i < filter->count; i++) {
		if (rte_is_same_ether_addr(&filter->mac[i], mac)) {
			LOG(DEBUG,
			    "%s: %s mac " ETH_ADDR_FMT " already filtered (refs=%u)",
			    iface->name,
			    mac_type,
			    ETH_ADDR_SPLIT(mac),
			    filter->refcnt[i]++);
			return 0;
		}
	}
	if (i == ARRAY_DIM(filter->mac))
		return errno_log(ENOSPC, mac_type);

	filter->mac[i] = *mac;
	filter->refcnt[i] = 1;
	filter->count++;

	LOG(INFO,
	    "%s: enabling %s " ETH_ADDR_FMT " mac filter",
	    iface->name,
	    mac_type,
	    ETH_ADDR_SPLIT(mac));

	if (filter->flags & MAC_FILTER_F_ALL)
		return 0;

	if (multicast)
		ret = rte_eth_dev_set_mc_addr_list(port->port_id, filter->mac, filter->count);
	else
		ret = rte_eth_dev_mac_addr_add(port->port_id, &filter->mac[i], 0);

	if (ret == -ENOSPC || ret == -EOPNOTSUPP) {
		if (ret == -ENOSPC) {
			filter->flags |= MAC_FILTER_F_NOSPC;
			filter->hw_limit = filter->count - 1;
			LOG(WARNING, "%s: %s: %s", iface->name, mac_type, rte_strerror(-ret));
		} else {
			filter->flags |= MAC_FILTER_F_UNSUPP;
			LOG(NOTICE, "%s: %s: %s", iface->name, mac_type, rte_strerror(-ret));
		}

		mac_type = multicast ? "allmulti" : "promisc";
		LOG(NOTICE, "%s: enabling %s", iface->name, mac_type);

		// promisc and allmulti enable is a noop if already enabled
		if (multicast)
			ret = rte_eth_allmulticast_enable(port->port_id);
		else
			ret = rte_eth_promiscuous_enable(port->port_id);

		if (ret == 0)
			filter->flags |= MAC_FILTER_F_ALL;
	}

	if (ret < 0) {
		filter->count--;
		return errno_log(-ret, mac_type);
	}

	return 0;
}

static int port_mac_del(struct iface *iface, const struct rte_ether_addr *mac) {
	struct iface_info_port *port = (struct iface_info_port *)iface->info;
	struct mac_filter *filter;
	const char *mac_type;
	bool multicast;
	uint8_t i;
	int ret;

	if (mac == NULL || !(rte_is_multicast_ether_addr(mac) || rte_is_unicast_ether_addr(mac)))
		return errno_set(EINVAL);

	if (rte_is_same_ether_addr(mac, &port->mac))
		return 0;

	multicast = rte_is_multicast_ether_addr(mac);
	if (multicast) {
		mac_type = "multicast";
		filter = &port->mcast_filter;
	} else {
		mac_type = "unicast";
		filter = &port->ucast_filter;
	}

	for (i = 0; i < filter->count; i++) {
		if (rte_is_same_ether_addr(&filter->mac[i], mac))
			goto found;
	}
	return errno_log(ENOENT, mac_type);

found:
	if (--filter->refcnt[i] > 0) {
		LOG(DEBUG,
		    "%s: %s mac " ETH_ADDR_FMT " still filtered (refs=%u)",
		    iface->name,
		    mac_type,
		    ETH_ADDR_SPLIT(mac),
		    filter->refcnt[i]);
		return 0;
	}

	LOG(INFO,
	    "%s: removing %s " ETH_ADDR_FMT " mac filter",
	    iface->name,
	    mac_type,
	    ETH_ADDR_SPLIT(mac));

	if (i + 1 < filter->count) {
		// shift other addresses and ref counts left
		memmove(&filter->mac[i],
			&filter->mac[i + 1],
			(filter->count - i - 1) * sizeof(filter->mac[i]));
		memmove(&filter->refcnt[i],
			&filter->refcnt[i + 1],
			(filter->count - i - 1) * sizeof(filter->refcnt[i]));
	}
	filter->count--;

	if (filter->flags & MAC_FILTER_F_ALL) {
		if (filter->count > 0 && filter->flags & MAC_FILTER_F_UNSUPP)
			return 0;
		if (filter->count > filter->hw_limit && filter->flags & MAC_FILTER_F_NOSPC)
			return 0;
		filter->flags = 0;
		filter->hw_limit = 0;
		if (multicast)
			ret = rte_eth_allmulticast_disable(port->port_id);
		else
			ret = rte_eth_promiscuous_disable(port->port_id);
		if (ret < 0)
			LOG(WARNING,
			    "%s: %s disable: %s",
			    iface->name,
			    multicast ? "allmulti" : "promisc",
			    rte_strerror(-ret));
	}

	if (multicast)
		ret = rte_eth_dev_set_mc_addr_list(port->port_id, filter->mac, filter->count);
	else
		ret = rte_eth_dev_mac_addr_remove(port->port_id, (struct rte_ether_addr *)mac);

	if (ret < 0)
		LOG(WARNING, "%s: %s: %s", iface->name, mac_type, rte_strerror(-ret));

	return 0;
}

static void port_to_api(void *info, const struct iface *iface) {
	const struct iface_info_port *port = (const struct iface_info_port *)iface->info;
	struct gr_iface_info_port *api = info;
	struct rte_eth_dev_info dev_info;

	memccpy(api->devargs, port->devargs, 0, sizeof(api->devargs));
	api->mac = port->mac;
	api->n_rxq = port->n_rxq;
	api->n_txq = port->n_txq;
	api->rxq_size = port->rxq_size;
	api->txq_size = port->txq_size;

	if (rte_eth_dev_info_get(port->port_id, &dev_info) == 0) {
		memccpy(api->driver_name, dev_info.driver_name, 0, sizeof(api->driver_name));
	} else {
		memccpy(api->driver_name, "unknown", 0, sizeof(api->driver_name));
	}
}

static struct event *link_event;

static void link_event_cb(evutil_socket_t, short, void *) {
	unsigned max_sleep_us, rx_buffer_us;
	struct rte_eth_rxq_info qinfo;
	struct rte_eth_link link;
	struct queue_map *qmap;
	struct worker *worker;
	const struct iface *i;
	struct iface *iface;

	STAILQ_FOREACH (worker, &workers, next) {
		if (gr_args()->poll_mode)
			max_sleep_us = 0;
		else
			max_sleep_us = 1000; // unreasonably long maximum (1ms)

		arrforeach (qmap, worker->rxqs) {
			i = port_ifaces[qmap->port_id];
			if (i == NULL)
				continue;
			iface = iface_from_id(i->id);
			if (iface == NULL)
				continue;

			if (rte_eth_link_get_nowait(qmap->port_id, &link) < 0) {
				LOG(INFO, "%s: link status down", iface->name);
				iface->state &= ~GR_IFACE_S_RUNNING;
				continue;
			}
			if (link.link_status == RTE_ETH_LINK_UP) {
				if (!(iface->state & GR_IFACE_S_RUNNING)) {
					LOG(INFO, "%s: link status up", iface->name);
					iface->state |= GR_IFACE_S_RUNNING;
				}
			} else {
				if (iface->state & GR_IFACE_S_RUNNING) {
					LOG(INFO, "%s: link status down", iface->name);
					iface->state &= ~GR_IFACE_S_RUNNING;
				}
				continue;
			}
			if (gr_args()->poll_mode)
				continue;

			switch (link.link_speed) {
			case RTE_ETH_SPEED_NUM_NONE:
			case RTE_ETH_SPEED_NUM_UNKNOWN:
				continue;
			}
			if (rte_eth_rx_queue_info_get(qmap->port_id, qmap->queue_id, &qinfo) < 0)
				continue;

			rx_buffer_us = queue_buffer_us(link.link_speed, qinfo.nb_desc);
			if (rx_buffer_us < max_sleep_us)
				max_sleep_us = rx_buffer_us;
		}
		if (atomic_exchange(&worker->max_sleep_us, max_sleep_us) != max_sleep_us)
			LOG(INFO, "[CPU %u] worker max sleep %uus", worker->cpu_id, max_sleep_us);
	}
}

static int lsc_port_cb(uint16_t, enum rte_eth_event_type, void *, void *) {
	// This callback may be executed from any dataplane or DPDK thread.
	// In order to serialize the update of port status, propagate the callback
	// event to the event loop running in the main lcore.
	event_active(link_event, 0, 0);
	return 0;
}

static void port_init(struct event_base *base) {
	link_event = event_new(base, -1, EV_PERSIST | EV_FINALIZE, link_event_cb, NULL);
	if (link_event == NULL)
		ABORT("event_new() failed");
	// Not all drivers support triggering link status change events.
	// Ensure the link_event is triggered at least once every second.
	struct timeval tv = {.tv_sec = 1};
	if (event_add(link_event, &tv) < 0)
		ABORT("event_add() failed");
	rte_eth_dev_callback_register(RTE_ETH_ALL, RTE_ETH_EVENT_INTR_LSC, lsc_port_cb, NULL);
}

static void port_fini(struct event_base *) {
	rte_eth_dev_callback_unregister(RTE_ETH_ALL, RTE_ETH_EVENT_INTR_LSC, lsc_port_cb, NULL);
	event_free(link_event);
	link_event = NULL;
}

static struct iface_type iface_type_port = {
	.id = GR_IFACE_TYPE_PORT,
	.name = "port",
	.info_size = sizeof(struct iface_info_port),
	.init = iface_port_init,
	.reconfig = iface_port_reconfig,
	.fini = iface_port_fini,
	.get_eth_addr = port_mac_get,
	.add_eth_addr = port_mac_add,
	.del_eth_addr = port_mac_del,
	.to_api = port_to_api,
};

static struct gr_module port_module = {
	.init = port_init,
	.fini = port_fini,
};

RTE_INIT(port_constructor) {
	iface_type_register(&iface_type_port);
	gr_register_module(&port_module);
}
