// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_config.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
#include <gr_eth.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_mempool.h>
#include <gr_module.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_net.h>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define TUN_TAP_DEV_PATH "/dev/net/tun"

static struct rte_mempool *loopback_pool;
static struct event_base *ev_base;

GR_IFACE_INFO(GR_IFACE_TYPE_LOOPBACK, iface_info_loopback, {
	int fd;
	struct event *ev;
	struct rte_ether_addr mac;
});

static void finalize_fd(struct event *ev, void * /*priv*/) {
	int fd = event_get_fd(ev);
	if (fd >= 0)
		close(fd);
}

static int loopback_mac_get(const struct iface *iface, struct rte_ether_addr *mac) {
	struct iface_info_loopback *lo = iface_info_loopback(iface);
	*mac = lo->mac;
	return 0;
}

void loopback_tx(struct rte_mbuf *m) {
	struct mbuf_data *d = mbuf_data(m);
	struct iface_info_loopback *lo;
	struct rte_ether_hdr *eth;
	struct iface_stats *stats;
	char *data = NULL;

	lo = iface_info_loopback(d->iface);

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if (rte_is_unicast_ether_addr(&eth->dst_addr))
		loopback_mac_get(d->iface, &eth->dst_addr);
	loopback_mac_get(d->iface, &eth->src_addr);

	if (rte_pktmbuf_linearize(m) == 0) {
		data = rte_pktmbuf_mtod(m, char *);
	} else {
		data = rte_malloc(NULL, rte_pktmbuf_pkt_len(m), 0);
		if (data == NULL) {
			LOG(ERR, "rte_malloc failed %s", rte_strerror(rte_errno));
			goto end;
		}
		// with a non-contiguous mbuf, rte_pktmbuf_read returns a pointer
		// to the user provided buffer.
		rte_pktmbuf_read(m, 0, rte_pktmbuf_pkt_len(m), data);
	}

	// Do not retry even in case of  if EAGAIN || EWOULDBLOCK
	// If the tun device queue is full, something really bad is
	// already happening on the management plane side.
	if (write(lo->fd, data, rte_pktmbuf_pkt_len(m)) != rte_pktmbuf_pkt_len(m)) {
		// The user messed up and removed gr-loopX
		// release resources on our side to try to recover
		if (errno == EBADFD) {
			iface_destroy(d->iface->id);
		}
		LOG(ERR, "write to tap device failed %s", strerror(errno));
	}

	stats = iface_get_stats(rte_lcore_id(), d->iface->id);
	stats->tx_packets += 1;
	stats->tx_bytes += rte_pktmbuf_pkt_len(m);

	if (gr_config.log_packets)
		trace_log_packet(m, "tx", d->iface->name);

	// TODO: add a trace for that fake node
	if (gr_mbuf_is_traced(m))
		gr_mbuf_trace_finish(m);
end:
	if (!rte_pktmbuf_is_contiguous(m))
		rte_free(data);
	rte_pktmbuf_free(m);
}

static void iface_loopback_poll(evutil_socket_t, short reason, void *ev_iface) {
	struct iface_info_loopback *lo;
	struct iface *iface = ev_iface;
	struct eth_input_mbuf_data *e;
	struct rte_ether_hdr *eth;
	struct iface_stats *stats;
	struct rte_mbuf *mbuf;
	size_t read_len;
	size_t len;
	char *data;

	lo = iface_info_loopback(iface);

	if (reason & EV_CLOSED) {
		// The user messed up and removed gr-loopX
		LOG(ERR, "tap device %s deleted", iface->name);
		iface_destroy(iface->id);
		return;
	}

	mbuf = rte_pktmbuf_alloc(loopback_pool);
	if (!mbuf) {
		LOG(ERR, "rte_pktmbuf_alloc %s", rte_strerror(rte_errno));
		goto err;
	}

	read_len = iface->mtu + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN;
	if ((data = rte_pktmbuf_append(mbuf, read_len)) == NULL) {
		LOG(ERR, "rte_pktmbuf_alloc %s", rte_strerror(rte_errno));
		goto err;
	}

	if ((len = read(lo->fd, data, read_len)) <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		LOG(ERR, "read from tun device %s failed %s", iface->name, strerror(errno));
		goto err;
	}

	rte_pktmbuf_trim(mbuf, read_len - len);
	eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

	if (rte_is_unicast_ether_addr(&eth->dst_addr))
		loopback_mac_get(iface, &eth->dst_addr);

	// packet sent from linux tun iface, no need to compute checksum;
	mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD;
	mbuf->packet_type = rte_net_get_ptype(mbuf, NULL, RTE_PTYPE_ALL_MASK);

	e = eth_input_mbuf_data(mbuf);
	e->iface = iface;
	e->domain = ETH_DOMAIN_LOOPBACK;

	stats = iface_get_stats(rte_lcore_id(), iface->id);
	stats->rx_packets += 1;
	stats->rx_bytes += rte_pktmbuf_pkt_len(mbuf);

	if (gr_config.log_packets)
		trace_log_packet(mbuf, "rx", iface->name);

	// TODO: add trace for that fake node

	post_to_stack(loopback_get_control_id(), mbuf);
	return;

err:
	rte_pktmbuf_free(mbuf);
}

struct iface *iface_loopback_create(uint16_t vrf_id) {
	struct gr_iface conf = {.type = GR_IFACE_TYPE_LOOPBACK, .mtu = 1500, .vrf_id = vrf_id};
	snprintf(conf.name, sizeof(conf.name), "gr-loop%d", vrf_id);
	return iface_create(&conf, NULL);
}

int iface_loopback_delete(uint16_t vrf_id) {
	const struct iface *i = NULL;
	while ((i = iface_next(GR_IFACE_TYPE_LOOPBACK, i)) != NULL)
		if (i->vrf_id == vrf_id)
			return iface_destroy(i->id);

	return errno_set(ENODEV);
}

static int iface_loopback_init(struct iface *iface, const void * /* api_info */) {
	struct iface_info_loopback *lo = iface_info_loopback(iface);
	struct ifreq ifr;
	int ioctl_sock;
	int err_save;
	int flags;

	memset(&ifr, 0, sizeof(struct ifreq));
	memccpy(ifr.ifr_name, iface->name, 0, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_ONE_QUEUE | IFF_NO_PI;

	if ((ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		LOG(ERR, "socket(SOCK_DGRAM): %s", strerror(errno));
		goto err;
	}

	if ((lo->fd = open(TUN_TAP_DEV_PATH, O_RDWR)) < 0) {
		LOG(ERR, "open(%s): %s", TUN_TAP_DEV_PATH, strerror(errno));
		goto err;
	}

	if (ioctl(lo->fd, TUNSETIFF, &ifr) < 0) {
		LOG(ERR, "ioctl(TUNSETIFF): %s", strerror(errno));
		goto err;
	}

	flags = fcntl(lo->fd, F_GETFL);
	if (flags == -1) {
		LOG(ERR, "fcntl(F_GETFL): %s", strerror(errno));
		goto err;
	}

	flags |= O_NONBLOCK;
	if (fcntl(lo->fd, F_SETFL, flags) < 0) {
		LOG(ERR, "fcntl(F_SETFL): %s", strerror(errno));
		goto err;
	}

	if (ioctl(ioctl_sock, SIOCGIFFLAGS, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCGIFFLAGS): %s", strerror(errno));
		goto err;
	}

	ifr.ifr_flags |= IFF_UP | IFF_NOARP;
	if (ioctl(ioctl_sock, SIOCSIFFLAGS, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCSIFFLAGS): %s", strerror(errno));
		goto err;
	}

	if (ioctl(ioctl_sock, SIOCGIFHWADDR, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCGIFHWADDR) %s", strerror(errno));
		goto err;
	}
	memcpy(&lo->mac, ifr.ifr_hwaddr.sa_data, sizeof(lo->mac));

	iface->flags = GR_IFACE_F_UP;
	iface->state = GR_IFACE_S_RUNNING;
	lo->ev = event_new(
		ev_base,
		lo->fd,
		EV_READ | EV_CLOSED | EV_PERSIST | EV_FINALIZE,
		iface_loopback_poll,
		iface
	);

	if (lo->ev == NULL || event_add(lo->ev, NULL) < 0) {
		event_free(lo->ev);
		goto err;
	}
	close(ioctl_sock);
	return 0;

err:
	err_save = errno;
	if (lo->fd > 0)
		close(lo->fd);
	if (ioctl_sock > 0)
		close(ioctl_sock);
	return errno_set(err_save);
}

static int iface_loopback_fini(struct iface *iface) {
	struct iface_info_loopback *lo = iface_info_loopback(iface);
	event_free_finalize(0, lo->ev, finalize_fd);
	return 0;
}

static void loopback_module_init(struct event_base *base) {
	loopback_pool = gr_pktmbuf_pool_get(SOCKET_ID_ANY, RTE_GRAPH_BURST_SIZE);
	if (!loopback_pool)
		ABORT("pktmbuf_pool returned NULL");
	ev_base = base;
}

static void loopback_module_fini(struct event_base *) {
	gr_pktmbuf_pool_release(loopback_pool, RTE_GRAPH_BURST_SIZE);
}

static void iface_loopback_to_api(void * /* info */, const struct iface * /* iface */) { }

static struct iface_type iface_type_loopback = {
	.id = GR_IFACE_TYPE_LOOPBACK,
	.name = "loopback",
	.pub_size = 0,
	.priv_size = sizeof(struct iface_info_loopback),
	.init = iface_loopback_init,
	.fini = iface_loopback_fini,
	.to_api = iface_loopback_to_api,
	.get_eth_addr = loopback_mac_get,
};

static struct gr_module loopback_module = {
	.name = "iface loopback",
	.init = loopback_module_init,
	.fini = loopback_module_fini,
};

RTE_INIT(loopback_constructor) {
	iface_type_register(&iface_type_loopback);
	gr_register_module(&loopback_module);
}
