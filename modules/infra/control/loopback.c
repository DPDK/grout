// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "control_input.h"
#include "control_queue.h"
#include "eth.h"
#include "iface.h"
#include "log.h"
#include "loopback.h"
#include "mempool.h"
#include "module.h"
#include "netlink.h"
#include "vrf.h"

#include <gr_infra.h>
#include <gr_string.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_malloc.h>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

GR_LOG_TYPE("loopback");

#define TUN_TAP_DEV_PATH "/dev/net/tun"

#define GR_LOOPBACK_TUN_NAME_PREFIX "gr-loop"
// TUN device naming pattern: gr-loop{iface_id}
#define GR_LOOPBACK_TUN_NAME_PATTERN GR_LOOPBACK_TUN_NAME_PREFIX "%d"

static struct rte_mempool *loopback_pool;
static struct event_base *ev_base;

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

	lo = &iface_info_vrf(d->iface)->lo;

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
	struct iovec iov[2];
	struct tun_pi pi;
	size_t len;
	char *data;

	lo = &iface_info_vrf(iface)->lo;

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

	if ((data = rte_pktmbuf_append(mbuf, iface->mtu)) == NULL) {
		LOG(ERR, "rte_pktmbuf_append %s", rte_strerror(rte_errno));
		goto err;
	}

	iov[0].iov_base = &pi;
	iov[0].iov_len = sizeof(pi);
	iov[1].iov_base = data;
	iov[1].iov_len = iface->mtu;
	if ((len = readv(lo->fd, iov, ARRAY_DIM(iov))) <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			goto err;
		LOG(ERR, "read from tun device %s failed %s", iface->name, strerror(errno));
		goto err;
	}

	rte_pktmbuf_trim(mbuf, iface->mtu - (len - sizeof(pi)));

	// packet sent from linux tun iface, no need to compute checksum;
	mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD;

	switch (pi.proto) {
	case RTE_BE16(RTE_ETHER_TYPE_IPV4):
		mbuf->packet_type = RTE_PTYPE_L3_IPV4;
		break;
	case RTE_BE16(RTE_ETHER_TYPE_IPV6):
		mbuf->packet_type = RTE_PTYPE_L3_IPV6;
		break;
	default:
		LOG(ERR, "unknown proto: %#x", rte_be_to_cpu_16(pi.proto));
		goto err;
	}

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

int iface_loopback_create(struct iface *iface) {
	struct iface_info_vrf *vrf = iface_info_vrf(iface);
	struct iface_info_loopback *lo = &vrf->lo;
	char tun_name[IFNAMSIZ];
	struct ifreq ifr;
	int ioctl_sock;
	int err_save;
	int flags;

	lo->ev = NULL;

	if (iface->id == GR_VRF_DEFAULT_ID)
		gr_strcpy(tun_name, sizeof(tun_name), iface->name);
	else
		snprintf(tun_name, sizeof(tun_name), GR_LOOPBACK_TUN_NAME_PATTERN, iface->vrf_id);

	memset(&ifr, 0, sizeof(struct ifreq));
	gr_strcpy(ifr.ifr_name, IFNAMSIZ, tun_name);
	ifr.ifr_flags = IFF_TUN;

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

	if (netlink_link_set_admin_state(iface->cp_id, false, false) < 0) {
		LOG(ERR, "netlink_link_set_admin_state(false): %s", strerror(errno));
		goto err;
	}

	if (netlink_link_set_admin_state(iface->cp_id, true, false) < 0) {
		LOG(ERR, "netlink_link_set_admin_state(true): %s", strerror(errno));
		goto err;
	}

	lo->ev = event_new(
		ev_base,
		lo->fd,
		EV_READ | EV_CLOSED | EV_PERSIST | EV_FINALIZE,
		iface_loopback_poll,
		iface
	);

	if (lo->ev == NULL || event_add(lo->ev, NULL) < 0)
		goto err;

	close(ioctl_sock);
	return 0;

err:
	err_save = errno;
	if (lo->ev) {
		event_del(lo->ev);
		event_free(lo->ev);
	}
	if (lo->fd > 0)
		close(lo->fd);
	if (ioctl_sock > 0)
		close(ioctl_sock);
	return errno_set(err_save);
}

int iface_loopback_destroy(struct iface *iface) {
	struct iface_info_loopback *lo = &iface_info_vrf(iface)->lo;
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

static struct gr_module loopback_module = {
	.name = "iface_loopback",
	.init = loopback_module_init,
	.fini = loopback_module_fini,
};

RTE_INIT(loopback_constructor) {
	iface_name_reserve(GR_LOOPBACK_TUN_NAME_PREFIX, true);
	gr_register_module(&loopback_module);
}
