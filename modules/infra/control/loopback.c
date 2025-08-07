// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "loopback.h"

#include <gr_control_input.h>
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

static void finalize_fd(struct event *ev, void * /*priv*/) {
	int fd = event_get_fd(ev);
	if (fd >= 0)
		close(fd);
}

static void iface_loopback_poll(evutil_socket_t, short reason, void *ev_iface) {
	struct eth_input_mbuf_data *e;
	struct iface_info_loopback *lo;
	struct iface *iface = ev_iface;
	struct rte_mbuf *mbuf;
	size_t read_len;
	size_t len;
	char *data;

	lo = (struct iface_info_loopback *)iface->info;

	if (reason & EV_CLOSED) {
		// The user messed up and removed gr-loopX
		LOG(ERR, "tun device %s deleted", iface->name);
		iface_destroy(iface->id);
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
			return;
		LOG(ERR, "read from tun device %s failed %s", iface->name, strerror(errno));
		goto err;
	}

	rte_pktmbuf_trim(mbuf, read_len - len);

	// packet sent from linux tun iface, no need to compute checksum;
	mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD;

	// We can't call rte_net_get_ptype directly as we do not have an ethernet frame.
	// An option would be to prepend/adjust every buffer, but let's set directly
	// the information we need instead.
	mbuf->packet_type = data[0] == 6 ? RTE_PTYPE_L3_IPV6 : RTE_PTYPE_L3_IPV4;

	// required by ip(6)_input
	e = eth_input_mbuf_data(mbuf);
	e->iface = iface;
	e->domain = ETH_DOMAIN_LOOPBACK;

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
	struct iface_info_loopback *lo = (struct iface_info_loopback *)iface->info;
	struct ifreq ifr;
	int ioctl_sock;
	int err_save;
	int flags;

	memset(&ifr, 0, sizeof(struct ifreq));
	memccpy(ifr.ifr_name, iface->name, 0, IFNAMSIZ);
	ifr.ifr_flags = IFF_TUN | IFF_POINTOPOINT | IFF_ONE_QUEUE;

	if ((ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		LOG(ERR, "socket %s", strerror(errno));
		goto err;
	}

	if ((lo->fd = open(TUN_TAP_DEV_PATH, O_RDWR)) < 0) {
		LOG(ERR, "open %s", strerror(errno));
		goto err;
	}

	if (ioctl(lo->fd, TUNSETIFF, &ifr) < 0) {
		LOG(ERR, "ioctl %s", strerror(errno));
		goto err;
	}

	flags = fcntl(lo->fd, F_GETFL);
	if (flags == -1) {
		LOG(ERR, "fnctl %s", strerror(errno));
		goto err;
	}

	flags |= O_NONBLOCK;
	if (fcntl(lo->fd, F_SETFL, flags) < 0) {
		LOG(ERR, "fnctl %s", strerror(errno));
		goto err;
	}

	if (ioctl(ioctl_sock, SIOCGIFFLAGS, &ifr) < 0) {
		LOG(ERR, "ioctl %s", strerror(errno));
		goto err;
	}

	ifr.ifr_flags |= IFF_UP;
	if (ioctl(ioctl_sock, SIOCSIFFLAGS, &ifr) < 0) {
		LOG(ERR, "ioctl %s", strerror(errno));
		goto err;
	}

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
	struct iface_info_loopback *lo = (struct iface_info_loopback *)iface->info;
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
	.info_size = sizeof(struct iface_info_loopback),
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
