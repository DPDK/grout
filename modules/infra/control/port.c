// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "config.h"
#include "event.h"
#include "iface.h"
#include "log.h"
#include "mempool.h"
#include "metrics.h"
#include "module.h"
#include "netlink.h"
#include "port.h"
#include "rcu.h"
#include "vec.h"
#include "vrf.h"
#include "worker.h"

#include <gr_infra.h>
#include <gr_string.h>

#include <numa.h>
#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_ether.h>

#include <dirent.h>
#include <fcntl.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

LOG_TYPE("port");

static void port_hide_netdev(struct iface_info_port *port);

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
		.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_VLAN_STRIP,
	},
	.txmode = {
		.offloads = 0,
	},
};

int port_configure(struct iface_info_port *p, uint16_t n_txq_min) {
	struct rte_eth_conf conf = default_port_config;
	int socket_id = SOCKET_ID_ANY;
	struct rte_eth_dev_info info;
	uint16_t rxq_size, txq_size;
	uint32_t mbuf_count;
	int ret;

	if (numa_available() != -1)
		socket_id = rte_eth_dev_socket_id(p->port_id);

	if ((ret = rte_eth_dev_info_get(p->port_id, &info)) < 0)
		return errno_log(-ret, "rte_eth_dev_info_get");

	if (p->n_rxq == 0)
		p->n_rxq = 1;

	if (p->n_rxq > info.max_rx_queues)
		return errno_set(EOVERFLOW);

	// cap number of queues to device maximum
	p->n_txq = RTE_MIN(n_txq_min, info.max_tx_queues);

	if (strcmp(info.driver_name, "net_tap") == 0
	    || strcmp(info.driver_name, "net_virtio") == 0) {
		// force number of TX queues equal to requested RX queues
		p->n_txq = p->n_rxq;
		if (p->n_txq > info.max_tx_queues)
			return errno_set(EOVERFLOW);
	}

	if (p->n_txq < n_txq_min)
		LOG(NOTICE, "port %s TX queues limited to %u", p->devargs, p->n_txq);

	for (uint16_t q = 0; q < p->n_txq; q++)
		rte_spinlock_init(&p->txq_locks[q]);

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
	conf.txmode.offloads &= info.tx_offload_capa;
	if (info.dev_flags != NULL && *info.dev_flags & RTE_ETH_DEV_INTR_LSC) {
		conf.intr_conf.lsc = 1;
	}

	if ((ret = rte_eth_dev_configure(p->port_id, p->n_rxq, p->n_txq, &conf)) < 0)
		return errno_log(-ret, "rte_eth_dev_configure");

	p->rx_offloads = conf.rxmode.offloads;

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

	return 0;
}

static int port_up_down(struct iface *iface, bool up) {
	struct iface_info_port *p = iface_info_port(iface);
	int ret;

	if (up) {
		ret = rte_eth_dev_set_link_up(p->port_id);
		switch (ret) {
		case 0:
		case -ENOSYS:
		case -EOPNOTSUPP:
			break;
		default:
			return errno_log(-ret, "rte_eth_dev_set_link_up");
		}
		iface->flags |= GR_IFACE_F_UP;
	} else {
		ret = rte_eth_dev_set_link_down(p->port_id);
		switch (ret) {
		case 0:
		case -ENOSYS:
		case -EOPNOTSUPP:
			break;
		default:
			return errno_log(-ret, "rte_eth_dev_set_link_down");
		}
		iface->flags &= ~GR_IFACE_F_UP;
	}

	return 0;
}

static int port_mac_set(struct iface *iface, const struct rte_ether_addr *mac) {
	struct iface_info_port *p = iface_info_port(iface);
	int ret;

	if (!rte_is_zero_ether_addr(mac)) {
		struct rte_ether_addr mut_mac = *mac;
		if ((ret = rte_eth_dev_default_mac_addr_set(p->port_id, &mut_mac)) < 0)
			return errno_log(-ret, "rte_eth_dev_default_mac_addr_set");
		p->mac = mut_mac;
	} else if ((ret = rte_eth_macaddr_get(p->port_id, &p->mac)) < 0) {
		return errno_log(-ret, "rte_eth_macaddr_get");
	}

	return 0;
}

static int port_promisc_set(struct iface *iface, bool enabled) {
	struct iface_info_port *p = iface_info_port(iface);
	int ret;

	if (iface->state & GR_IFACE_S_PROMISC_FIXED)
		return 0; // promisc is forced to filter unicast addresses, leave it as-is

	if (enabled)
		ret = rte_eth_promiscuous_enable(p->port_id);
	else
		ret = rte_eth_promiscuous_disable(p->port_id);

	switch (ret) {
	case 0:
	case -ENOSYS:
	case -EOPNOTSUPP:
		break;
	default:
		return errno_log(-ret, "rte_eth_promiscuous_{en,dis}able");
	}

	if (rte_eth_promiscuous_get(p->port_id) == 1)
		iface->flags |= GR_IFACE_F_PROMISC;
	else
		iface->flags &= ~GR_IFACE_F_PROMISC;

	return 0;
}

static int port_mtu_set(struct iface *iface, uint16_t mtu) {
	struct iface_info_port *p = iface_info_port(iface);
	int ret;

	p->started = false;
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
	if ((ret = rte_eth_dev_stop(p->port_id)) < 0)
		return errno_log(-ret, "rte_eth_dev_stop");
	ret = rte_eth_dev_set_mtu(p->port_id, mtu);
	switch (ret) {
	case 0:
	case -ENOSYS:
	case -EOPNOTSUPP:
		break;
	default:
		return errno_log(-ret, "rte_eth_dev_set_mtu");
	}
	if ((ret = rte_eth_dev_start(p->port_id)) < 0)
		return errno_log(-ret, "rte_eth_dev_start");
	p->started = true;
	iface->mtu = mtu;

	vec_foreach (struct iface *s, iface->subinterfaces)
		s->mtu = iface->mtu;

	return 0;
}

static int iface_port_reconfig(
	struct iface *iface,
	uint64_t set_attrs,
	const struct gr_iface *,
	const void *api_info
) {
	struct iface_info_port *p = iface_info_port(iface);
	const struct gr_iface_info_port *api = api_info;
	bool needs_configure = false;
	int ret;

	if (!(set_attrs
	      & (GR_PORT_SET_N_RXQS | GR_PORT_SET_N_TXQS | GR_PORT_SET_Q_SIZE | GR_PORT_SET_MAC)))
		return 0;

	if (set_attrs & GR_PORT_SET_N_RXQS) {
		p->n_rxq = api->n_rxq;
		needs_configure = true;
	}
	if (set_attrs & GR_PORT_SET_N_TXQS) {
		p->n_txq = api->n_txq;
		needs_configure = true;
	}
	if (set_attrs & GR_PORT_SET_Q_SIZE) {
		p->rxq_size = api->rxq_size;
		p->txq_size = api->txq_size;
		needs_configure = true;
	}

	if (p->started && (needs_configure || p->needs_reset)) {
		p->started = false;
		rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
		if (p->needs_reset) {
			p->needs_reset = false;
			needs_configure = true;
			if ((ret = rte_eth_dev_reset(p->port_id)) < 0)
				return errno_log(-ret, "rte_eth_dev_reset");
		} else if ((ret = rte_eth_dev_stop(p->port_id)) < 0) {
			return errno_log(-ret, "rte_eth_dev_stop");
		}
	}

	if (needs_configure) {
		if ((ret = port_unplug(p)) < 0)
			return ret;

		if ((ret = port_configure(p, CPU_COUNT(&gr_config.datapath_cpus))) < 0)
			return ret;

		// generate a list of ports including the one being configured/created
		vec struct iface_info_port **ports = NULL;
		struct iface *i = NULL;
		bool found = false;
		while ((i = iface_next(GR_IFACE_TYPE_PORT, i)) != NULL) {
			struct iface_info_port *port = iface_info_port(i);
			if (port == p)
				found = true;
			vec_add(ports, port);
		}
		if (!found) {
			// port is being created, not present in the global list yet
			vec_add(ports, p);
		}
		ret = worker_queue_distribute(&gr_config.datapath_cpus, ports);
		vec_free(ports);
		if (ret < 0)
			return ret;

		// always enable allmulti
		if ((ret = rte_eth_allmulticast_enable(p->port_id)) < 0) {
			LOG(ERR, "rte_eth_allmulticast_enable failed %s", rte_strerror(-ret));
			if ((ret = rte_eth_promiscuous_enable(p->port_id)) < 0)
				return errno_log(-ret, "rte_eth_promiscuous_enable failed");
			else
				iface->state |= GR_IFACE_S_PROMISC_FIXED;
		} else {
			iface->state |= GR_IFACE_S_ALLMULTI;
		}

		if ((ret = port_plug(p)) < 0)
			return ret;
	}

	if (set_attrs & GR_PORT_SET_MAC && (ret = iface_set_eth_addr(iface, &api->mac)) < 0)
		return ret;

	if (!p->started && (ret = rte_eth_dev_start(p->port_id)) < 0)
		return errno_log(-ret, "rte_eth_dev_start");

	p->started = true;

	return 0;
}

static const struct iface *port_ifaces[RTE_MAX_ETHPORTS];

// Read the physical port name from sysfs (e.g. "p1" on multi-port NICs).
static int read_phys_port_name(const char *ifname, char *buf, size_t size) {
	char path[PATH_MAX];
	ssize_t len;
	int fd;

	snprintf(path, sizeof(path), "/sys/class/net/%s/phys_port_name", ifname);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	len = read(fd, buf, size - 1);
	close(fd);
	if (len <= 0)
		return -errno;
	while (buf[len - 1] == '\n')
		len--;
	buf[len] = '\0';

	return 0;
}

// Build a predictable name similar to systemd/udev but with "_gr" prefix.
// If ifname is not NULL, also append "n<phys_port_name>" when available
// (e.g. enp24s0np1 -> _grp24s0np1).
static int port_netdev_name(char *buf, size_t size, const char *pci_addr, const char *ifname) {
	uint32_t domain, bus, slot, func;
	char phys_port[IFNAMSIZ];
	size_t n = 0;

	if (sscanf(pci_addr, "%x:%x:%x.%x", &domain, &bus, &slot, &func) != 4)
		goto err;

	if (domain > 0)
		SAFE_BUF(snprintf, size, "_grP%up%us%u", domain, bus, slot);
	else
		SAFE_BUF(snprintf, size, "_grp%us%u", bus, slot);

	if (func > 0)
		SAFE_BUF(snprintf, size, "f%u", func);

	if (ifname != NULL && read_phys_port_name(ifname, phys_port, sizeof(phys_port)) == 0)
		SAFE_BUF(snprintf, size, "n%s", phys_port);

	return 0;
err:
	return -1;
}

static void port_hide_netdev(struct iface_info_port *port) {
	char sysfs_path[PATH_MAX];
	char new_name[IFNAMSIZ];
	char ifalias[IFALIASZ];
	struct dirent *entry;
	unsigned ifindex;
	DIR *dir;

	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/pci/devices/%s/net", port->devargs);

	dir = opendir(sysfs_path);
	if (dir == NULL)
		return;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		if (port_netdev_name(new_name, sizeof(new_name), port->devargs, entry->d_name) < 0)
			break;

		ifindex = if_nametoindex(entry->d_name);
		if (ifindex == 0) {
			LOG(WARNING, "if_nametoindex(%s): %s", entry->d_name, strerror(errno));
			break;
		}

		port->linux_ifname = strdup(entry->d_name);
		if (port->linux_ifname == NULL) {
			LOG(WARNING, "strdup: %s", strerror(errno));
			break;
		}

		if (netlink_link_set_name(ifindex, new_name) < 0) {
			LOG(WARNING,
			    "rename %s -> %s: %s",
			    entry->d_name,
			    new_name,
			    strerror(errno));
			free(port->linux_ifname);
			port->linux_ifname = NULL;
		} else {
			LOG(INFO, "renamed %s -> %s", entry->d_name, new_name);
		}

		snprintf(
			ifalias,
			sizeof(ifalias),
			"Grout port %s (was %s) -- do not configure",
			port->devargs,
			entry->d_name
		);
		if (netlink_set_ifalias(ifindex, ifalias) < 0)
			LOG(WARNING, "netlink_set_ifalias: %s", strerror(errno));

		break;
	}

	closedir(dir);
}

static void port_restore_netdev(struct iface_info_port *port) {
	char sysfs_path[PATH_MAX];
	struct dirent *entry;
	unsigned ifindex;
	DIR *dir;

	if (port->linux_ifname == NULL)
		return;

	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/pci/devices/%s/net", port->devargs);

	dir = opendir(sysfs_path);
	if (dir == NULL)
		goto out;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		ifindex = if_nametoindex(entry->d_name);
		if (ifindex == 0) {
			LOG(WARNING, "if_nametoindex(%s): %s", entry->d_name, strerror(errno));
			break;
		}

		netlink_set_ifalias(ifindex, "");
		if (netlink_link_set_name(ifindex, port->linux_ifname) < 0) {
			LOG(WARNING,
			    "rename %s -> %s: %s",
			    entry->d_name,
			    port->linux_ifname,
			    strerror(errno));
		} else {
			LOG(INFO, "restored %s -> %s", entry->d_name, port->linux_ifname);
		}
		break;
	}
	closedir(dir);
out:
	free(port->linux_ifname);
	port->linux_ifname = NULL;
}

static int iface_port_fini(struct iface *iface) {
	struct iface_info_port *port = iface_info_port(iface);
	vec struct iface_info_port **ports = NULL;
	struct rte_eth_dev_info info = {0};
	struct iface *i = NULL;
	int ret;

	if (worker_count() > 0) {
		// unplug port from all workers
		while ((i = iface_next(GR_IFACE_TYPE_PORT, i)) != NULL) {
			struct iface_info_port *p = iface_info_port(i);
			if (p != port)
				vec_add(ports, p);
		}
		ret = worker_queue_distribute(&gr_config.datapath_cpus, ports);
		vec_free(ports);
		if (ret < 0)
			return errno_log(-ret, "worker_queue_reassign");
	}

	while ((i = iface_next(GR_IFACE_TYPE_UNDEF, i)) != NULL) {
		if (i->domain_id == iface->id) {
			i->vrf_id = vrf_default_get_or_create();
			if (i->vrf_id != GR_VRF_ID_UNDEF)
				vrf_incref(i->vrf_id);
			i->mode = GR_IFACE_MODE_VRF;
			i->domain_id = GR_IFACE_ID_UNDEF;
			event_push(GR_EVENT_IFACE_POST_RECONFIG, i);
		}
	}

	port_ifaces[port->port_id] = NULL;

	port_restore_netdev(port);
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

	return ret;
}

static int iface_port_init(struct iface *iface, const void *api_info) {
	struct iface_info_port *port = iface_info_port(iface);
	const struct gr_iface_info_port *api = api_info;
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct rte_dev_iterator iterator;
	struct rte_eth_dev_info info;
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
	if (rte_eth_dev_info_get(port_id, &info) < 0)
		return errno_set(-ret);
	port->virtio_offloads = strcmp(info.driver_name, "net_virtio") == 0
		&& (info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM) != 0;

	port->devargs = strndup(api->devargs, GR_PORT_DEVARGS_SIZE);
	if (port->devargs == NULL) {
		ret = errno_set(ENOMEM);
		goto fail;
	}

	port_hide_netdev(port);

	ret = iface_port_reconfig(iface, IFACE_SET_ALL, NULL, api_info);
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

static int iface_port_attach_peer(struct iface *domain, struct iface *iface) {
	if (iface->type != GR_IFACE_TYPE_PORT)
		return errno_set(EMEDIUMTYPE);

	iface->mode = GR_IFACE_MODE_XC;
	iface->domain_id = domain->id;

	return 0;
}

static int iface_port_detach_peer(struct iface *, struct iface *iface) {
	if (iface->type != GR_IFACE_TYPE_PORT)
		return errno_set(EMEDIUMTYPE);

	iface->mode = GR_IFACE_MODE_VRF;
	iface->domain_id = GR_IFACE_ID_UNDEF;

	return 0;
}

const struct iface *port_get_iface(uint16_t port_id) {
	return port_ifaces[port_id];
}

static int port_mac_get(const struct iface *iface, struct rte_ether_addr *mac) {
	struct iface_info_port *port = iface_info_port(iface);
	*mac = port->mac;
	return 0;
}

static int port_mac_add(struct iface *iface, struct iface_mac *m) {
	struct iface_info_port *port = iface_info_port(iface);
	int ret;

	ret = rte_eth_dev_mac_addr_add(port->port_id, &m->mac, 0);
	if (ret == 0) {
		m->hardware = true;
	} else if (ret == -ENOSPC || ret == -EOPNOTSUPP) {
		if (ret == -ENOSPC)
			LOG(INFO, "%s: %s", iface->name, rte_strerror(-ret));
		else
			LOG(DEBUG, "%s: %s", iface->name, rte_strerror(-ret));

		ret = 0;
		if ((iface->state & GR_IFACE_S_PROMISC_FIXED) == 0) {
			ret = rte_eth_promiscuous_enable(port->port_id);
			if (ret == 0) {
				LOG(INFO, "%s: enabled promisc", iface->name);
				iface->state |= GR_IFACE_S_PROMISC_FIXED;
			} else {
				LOG(INFO, "%s: %s", iface->name, rte_strerror(-ret));
			}
		}
	}

	if (ret < 0)
		return errno_set(-ret);

	return 0;
}

static int port_mac_del(struct iface *iface, struct iface_mac *m) {
	struct iface_info_port *port = iface_info_port(iface);
	int ret;

	if (m->hardware) {
		ret = rte_eth_dev_mac_addr_remove(port->port_id, &m->mac);
		if (ret < 0 && ret != -ENOTSUP)
			LOG(WARNING, "%s: %s", iface->name, rte_strerror(-ret));
	}

	if (iface->state & GR_IFACE_S_PROMISC_FIXED) {
		bool disable_promisc = true;

		vec_foreach_ref (struct iface_mac *m2, iface->macs) {
			if (m == m2 || m2->hardware)
				continue;
			ret = rte_eth_dev_mac_addr_add(port->port_id, &m2->mac, 0);
			if (ret < 0) {
				LOG(INFO, "%s: %s", iface->name, rte_strerror(-ret));
				disable_promisc = false;
				break;
			}
			m2->hardware = true;
		}

		if (disable_promisc) {
			ret = rte_eth_promiscuous_disable(port->port_id);
			if (ret < 0 && ret != -ENOTSUP) {
				LOG(NOTICE,
				    "%s: promisc disable: %s",
				    iface->name,
				    rte_strerror(-ret));
			} else {
				LOG(INFO, "%s: disabled promisc", iface->name);
				iface->state &= ~GR_IFACE_S_PROMISC_FIXED;
			}
		}
	}

	return 0;
}

static void port_to_api(void *info, const struct iface *iface) {
	const struct iface_info_port *port = iface_info_port(iface);
	struct gr_iface_info_port *api = info;
	struct rte_eth_dev_info dev_info;

	api->base = port->base;
	gr_strcpy(api->devargs, sizeof(api->devargs), port->devargs);

	if (rte_eth_dev_info_get(port->port_id, &dev_info) == 0) {
		gr_strcpy(api->driver_name, sizeof(api->driver_name), dev_info.driver_name);
	} else {
		gr_strcpy(api->driver_name, sizeof(api->driver_name), "unknown");
	}
}

METRIC_GAUGE(m_rxqs, "iface_port_rxqs", "Number of RX queues.");
METRIC_GAUGE(m_txqs, "iface_port_txqs", "Number of TX queues.");
METRIC_GAUGE(m_rxq_size, "iface_port_rxq_size", "Number of descriptors in RX queues.");
METRIC_GAUGE(m_txq_size, "iface_port_txq_size", "Number of descriptors in TX queues.");
METRIC_COUNTER(m_rx_missed, "iface_port_rx_missed", "Number of packets dropped by HW.");
METRIC_COUNTER(m_tx_errors, "iface_port_tx_errors", "Number of TX failures.");

static void port_metrics_collect(struct metrics_ctx *ctx, const struct iface *iface) {
	const struct iface_info_port *port = iface_info_port(iface);
	struct rte_eth_dev_info dev_info;
	struct rte_eth_stats stats;

	if (rte_eth_dev_info_get(port->port_id, &dev_info) == 0)
		metrics_labels_add(ctx, "driver", dev_info.driver_name, NULL);
	else
		metrics_labels_add(ctx, "driver", "?", NULL);

	metric_emit(ctx, &m_rxqs, port->n_rxq);
	metric_emit(ctx, &m_txqs, port->n_txq);
	metric_emit(ctx, &m_rxq_size, port->rxq_size);
	metric_emit(ctx, &m_txq_size, port->txq_size);

	if (rte_eth_stats_get(port->port_id, &stats) == 0) {
		metric_emit(ctx, &m_rx_missed, stats.imissed);
		metric_emit(ctx, &m_tx_errors, stats.oerrors);
	}
}

static struct event *link_event;

static void link_event_cb(evutil_socket_t, short /*what*/, void * /*priv*/) {
	unsigned max_sleep_us, rx_buffer_us;
	struct rte_eth_rxq_info qinfo;
	struct rte_eth_link link;
	struct queue_map *qmap;
	struct worker *worker;
	const struct iface *i;
	struct iface *iface;

	STAILQ_FOREACH (worker, &workers, next) {
		if (gr_config.poll_mode)
			max_sleep_us = 0;
		else
			max_sleep_us = 1000; // unreasonably long maximum (1ms)

		vec_foreach_ref (qmap, worker->rxqs) {
			i = port_ifaces[qmap->port_id];
			if (i == NULL)
				continue;
			iface = iface_from_id(i->id);
			if (iface == NULL)
				continue;

			if (rte_eth_link_get_nowait(qmap->port_id, &link) < 0) {
				LOG(WARNING, "rte_eth_link_get_nowait: %s", strerror(rte_errno));
				continue;
			}
			iface->speed = link.link_speed;

			if (link.link_status == RTE_ETH_LINK_UP && (iface->flags & GR_IFACE_F_UP)) {
				if (!(iface->state & GR_IFACE_S_RUNNING)) {
					LOG(INFO, "%s: link status up", iface->name);
					iface->state |= GR_IFACE_S_RUNNING;
					event_push(GR_EVENT_IFACE_STATUS_UP, iface);
				}
			} else {
				if (iface->state & GR_IFACE_S_RUNNING) {
					LOG(INFO, "%s: link status down", iface->name);
					iface->state &= ~GR_IFACE_S_RUNNING;
					event_push(GR_EVENT_IFACE_STATUS_DOWN, iface);
				}
				continue;
			}
			if (gr_config.poll_mode)
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

static int lsc_port_cb(
	uint16_t /*port_id*/,
	enum rte_eth_event_type,
	void * /*cb_arg*/,
	void * /*ret_param*/
) {
	// This callback may be executed from any dataplane or DPDK thread.
	// In order to serialize the update of port status, propagate the callback
	// event to the event loop running in the main lcore.
	event_active(link_event, 0, 0);
	return 0;
}

static struct event *reset_event;
static vec uint16_t *reset_ports;
static pthread_mutex_t reset_ports_lock = PTHREAD_MUTEX_INITIALIZER;

static int intr_reset_cb(
	uint16_t port_id,
	enum rte_eth_event_type,
	void * /*cb_arg*/,
	void * /*ret_param*/
) {
	// Multiple VFs may be reset before reset_event is fired in the main loop.
	// Queue the port IDs in a vector protected by a mutex so that they are all
	// processed in port_reset_cb().
	pthread_mutex_lock(&reset_ports_lock);
	vec_add(reset_ports, port_id);
	pthread_mutex_unlock(&reset_ports_lock);
	// This callback may be executed from any dataplane or DPDK thread.
	// In order to serialize the reset of the port, propagate the callback
	// event to the event loop running in the main lcore.
	event_active(reset_event, 0, 0);
	return 0;
}

static void port_reset_cb(evutil_socket_t, short, void * /*priv*/) {
	vec uint16_t *port_ids;

	// reset the port_id queue
	pthread_mutex_lock(&reset_ports_lock);
	port_ids = reset_ports;
	reset_ports = NULL;
	pthread_mutex_unlock(&reset_ports_lock);

	vec_foreach (uint16_t pid, port_ids) {
		struct iface *iface = (struct iface *)port_get_iface(pid);
		if (iface != NULL) {
			struct iface_info_port *port = iface_info_port(iface);
			struct gr_iface_info_port api = {.mac = {{0}}};
			LOG(INFO, "%s: port %u reset", iface->name, pid);
			port->needs_reset = true;
			iface_port_reconfig(iface, GR_PORT_SET_MAC, NULL, &api);
		}
	}
	vec_free(port_ids);
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

	// register an interrupt callback for port hardware reset events
	reset_event = event_new(base, -1, EV_PERSIST | EV_FINALIZE, port_reset_cb, NULL);
	if (reset_event == NULL)
		ABORT("event_new() failed");
	rte_eth_dev_callback_register(RTE_ETH_ALL, RTE_ETH_EVENT_INTR_RESET, intr_reset_cb, NULL);
}

static void port_fini(struct event_base *) {
	rte_eth_dev_callback_unregister(RTE_ETH_ALL, RTE_ETH_EVENT_INTR_LSC, lsc_port_cb, NULL);
	event_free(link_event);
	link_event = NULL;
	rte_eth_dev_callback_unregister(RTE_ETH_ALL, RTE_ETH_EVENT_INTR_RESET, intr_reset_cb, NULL);
	event_free(reset_event);
	reset_event = NULL;
	vec_free(reset_ports);
}

static const struct iface_type iface_type_port = {
	.id = GR_IFACE_TYPE_PORT,
	.pub_size = sizeof(struct gr_iface_info_port),
	.priv_size = sizeof(struct iface_info_port),
	.init = iface_port_init,
	.reconfig = iface_port_reconfig,
	.fini = iface_port_fini,
	.attach_domain = iface_port_attach_peer,
	.detach_domain = iface_port_detach_peer,
	.get_eth_addr = port_mac_get,
	.add_eth_addr = port_mac_add,
	.del_eth_addr = port_mac_del,
	.set_eth_addr = port_mac_set,
	.set_mtu = port_mtu_set,
	.set_up_down = port_up_down,
	.set_promisc = port_promisc_set,
	.to_api = port_to_api,
	.metrics_collect = port_metrics_collect,
};

static struct module port_module = {
	.name = "iface_port",
	.init = port_init,
	.fini = port_fini,
};

static void port_unplug_cb(uint32_t /*event*/, const void *obj) {
	const struct iface *iface = obj;
	if (iface->type != GR_IFACE_TYPE_PORT)
		return;
	if (port_unplug(iface_info_port(iface)) < 0)
		LOG(WARNING, "port_unplug(%s): %s", iface->name, strerror(errno));
}

RTE_INIT(port_constructor) {
	iface_type_register(&iface_type_port);
	module_register(&port_module);
	event_subscribe(GR_EVENT_IFACE_PRE_REMOVE, port_unplug_cb);
}
