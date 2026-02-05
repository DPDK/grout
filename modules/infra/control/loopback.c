// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_input.h>
#include <gr_control_queue.h>
#include <gr_eth.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_mempool.h>
#include <gr_module.h>
#include <gr_netlink.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define TUN_TAP_DEV_PATH "/dev/net/tun"

#define GR_LOOPBACK_NAME_PATTERN "gr-vrf%d"
#define GR_LOOPBACK_TUN_NAME_PATTERN "gr-loop%d"

static struct rte_mempool *loopback_pool;
static struct event_base *ev_base;

GR_IFACE_INFO(GR_IFACE_TYPE_LOOPBACK, iface_info_loopback, {
	int fd;
	struct event *ev;
});

static void finalize_fd(struct event *ev, void * /*priv*/) {
	int fd = event_get_fd(ev);
	if (fd >= 0)
		close(fd);
}

void loopback_tx(void *obj, uintptr_t, const struct control_queue_drain *drain) {
	struct rte_mbuf *m = obj;
	struct mbuf_data *d = mbuf_data(m);
	struct iface_info_loopback *lo;
	struct iface_stats *stats;
	struct iovec iov[2];
	char *data = NULL;
	struct tun_pi pi;

	// Check if packet references deleted interface.
	if (drain != NULL && drain->event == GR_EVENT_IFACE_REMOVE && d->iface == drain->obj)
		goto end;

	lo = iface_info_loopback(d->iface);

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
	pi.flags = 0;
	if ((data[0] & 0xf0) == 0x40)
		pi.proto = RTE_BE16(RTE_ETHER_TYPE_IPV4);
	else if ((data[0] & 0xf0) == 0x60)
		pi.proto = RTE_BE16(RTE_ETHER_TYPE_IPV6);
	else {
		LOG(ERR, "Bad proto: 0x%x - drop packet", data[0]);
		goto end;
	}
	// Do not retry even in case of  if EAGAIN || EWOULDBLOCK
	// If the tun device queue is full, something really bad is
	// already happening on the management plane side.
	iov[0].iov_base = &pi;
	iov[0].iov_len = sizeof(pi);
	iov[1].iov_base = data;
	iov[1].iov_len = rte_pktmbuf_pkt_len(m);

	if (writev(lo->fd, iov, ARRAY_DIM(iov)) < 0) {
		// The user messed up and removed gr-loopX
		// release resources on our side to try to recover
		if (errno == EBADFD) {
			iface_destroy((struct iface *)d->iface);
		}
		LOG(ERR, "write to tun device failed %s", strerror(errno));
	}

	stats = iface_get_stats(rte_lcore_id(), d->iface->id);
	stats->cp_tx_packets += 1;
	stats->cp_tx_bytes += rte_pktmbuf_pkt_len(m);

end:
	if (!rte_pktmbuf_is_contiguous(m))
		rte_free(data);
	rte_pktmbuf_free(m);
}

static void iface_loopback_poll(evutil_socket_t, short reason, void *ev_iface) {
	struct iface *iface = ev_iface;
	struct iface_info_loopback *lo;
	struct eth_input_mbuf_data *e;
	struct iface_stats *stats;
	struct rte_mbuf *mbuf;
	size_t read_len;
	size_t len;
	char *data;

	lo = iface_info_loopback(iface);

	if (reason & EV_CLOSED) {
		// The user messed up and removed gr-loopX
		LOG(ERR, "tun device %s deleted", iface->name);
		iface_destroy(iface);
		return;
	}

	mbuf = rte_pktmbuf_alloc(loopback_pool);
	if (!mbuf) {
		LOG(ERR, "rte_pktmbuf_alloc %s", rte_strerror(rte_errno));
		goto err;
	}

	read_len = iface->mtu + sizeof(struct tun_pi);
	if ((data = rte_pktmbuf_append(mbuf, read_len)) == NULL) {
		LOG(ERR, "rte_pktmbuf_alloc %s", rte_strerror(rte_errno));
		goto err;
	}

	if ((len = read(lo->fd, data, read_len)) <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto err;
		LOG(ERR, "read from tun device %s failed %s", iface->name, strerror(errno));
		goto err;
	}

	rte_pktmbuf_trim(mbuf, read_len - len);

	// packet sent from linux tun iface, no need to compute checksum;
	mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD;

	// We can't call rte_net_get_ptype directly as we do not have an ethernet frame.
	// An option would be to prepend/adjust every buffer, but let's set directly
	// the information we need instead.
	mbuf->packet_type = (data[0] & 0xf0) == 0x60 ? RTE_PTYPE_L3_IPV6 : RTE_PTYPE_L3_IPV4;

	// required by ip(6)_input
	e = eth_input_mbuf_data(mbuf);
	e->iface = iface;
	e->domain = ETH_DOMAIN_LOOPBACK;

	if (post_to_stack(loopback_get_control_id(), mbuf) < 0) {
		LOG(ERR, "post_to_stack: %s", strerror(errno));
		goto err;
	}

	stats = iface_get_stats(rte_lcore_id(), iface->id);
	stats->cp_rx_packets += 1;
	stats->cp_rx_bytes += rte_pktmbuf_pkt_len(mbuf);

	return;

err:
	rte_pktmbuf_free(mbuf);
}

struct iface *iface_loopback_create(uint16_t vrf_id) {
	struct gr_iface conf = {.type = GR_IFACE_TYPE_LOOPBACK, .mtu = 1500, .vrf_id = vrf_id};

	if (vrf_id)
		snprintf(conf.name, sizeof(conf.name), GR_LOOPBACK_NAME_PATTERN, vrf_id);
	else
		memccpy(conf.name, "gr-loop0", 0, sizeof(conf.name));

	return iface_create(&conf, NULL);
}

int iface_loopback_delete(uint16_t vrf_id) {
	struct iface *i = NULL;
	while ((i = iface_next(GR_IFACE_TYPE_LOOPBACK, i)) != NULL)
		if (i->vrf_id == vrf_id)
			return iface_destroy(i);

	return errno_set(ENODEV);
}

static int iface_loopback_init(struct iface *iface, const void * /* api_info */) {
	struct iface_info_loopback *lo = iface_info_loopback(iface);
	char tun_name[IFNAMSIZ];
	struct ifreq ifr;
	int ioctl_sock;
	int err_save;
	int flags;

	if (iface->vrf_id)
		snprintf(tun_name, sizeof(tun_name), GR_LOOPBACK_TUN_NAME_PATTERN, iface->vrf_id);
	else
		memccpy(tun_name, iface->name, 0, sizeof(tun_name));

	memset(&ifr, 0, sizeof(struct ifreq));
	memccpy(ifr.ifr_name, tun_name, 0, IFNAMSIZ);
	ifr.ifr_flags = IFF_TUN | IFF_POINTOPOINT;

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

	if (ioctl(ioctl_sock, SIOCGIFINDEX, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCGIFINDEX): %s", strerror(errno));
		goto err;
	}
	iface->cp_id = ifr.ifr_ifindex;

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

	if (netlink_set_addr_gen_mode_none(iface->cp_id) < 0) {
		LOG(ERR, "netlink_set_addr_gen_mode_none: %s", strerror(errno));
		goto err;
	}

	if (netlink_link_set_admin_state(iface->cp_id, false) < 0) {
		LOG(ERR, "netlink_link_set_admin_state(false): %s", strerror(errno));
		goto err;
	}

	if (netlink_link_set_admin_state(iface->cp_id, true) < 0) {
		LOG(ERR, "netlink_link_set_admin_state(true): %s", strerror(errno));
		goto err;
	}

	iface->flags = GR_IFACE_F_UP;
	iface->state = GR_IFACE_S_RUNNING;
	iface->speed = RTE_ETH_SPEED_NUM_10G;
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

static const struct iface_type iface_type_loopback = {
	.id = GR_IFACE_TYPE_LOOPBACK,
	.pub_size = 0,
	.priv_size = sizeof(struct iface_info_loopback),
	.init = iface_loopback_init,
	.fini = iface_loopback_fini,
	.to_api = iface_loopback_to_api,
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
