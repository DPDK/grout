// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_config.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
#include <gr_eth.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_macro.h>
#include <gr_mempool.h>
#include <gr_module.h>
#include <gr_nh_control.h>
#include <gr_port.h>
#include <gr_rcu.h>
#include <gr_string.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_dev.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_net.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <vrf_priv.h>
#include <wchar.h>

#define TUN_TAP_DEV_PATH "/dev/net/tun"

static struct rte_mempool *cp_pool;
static struct event_base *ev_base;

static control_input_t port_output_id;

static void finalize_fd(struct event *ev, void * /*priv*/) {
	int fd = event_get_fd(ev);
	if (fd >= 0)
		close(fd);
}

void iface_cp_tx(struct rte_mbuf *m) {
	struct mbuf_data *d = mbuf_data(m);
	struct iface_stats *stats;
	char *data = NULL;

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
	if (write(d->iface->cp_fd, data, rte_pktmbuf_pkt_len(m)) != rte_pktmbuf_pkt_len(m)) {
		// The user messed up and removed the tap interface
		// release resources on our side to try to recover
		if (errno == EBADFD) {
			iface_destroy(d->iface->id);
		}
		LOG(ERR, "write to tap device failed %s", strerror(errno));
	}

	stats = iface_get_stats(rte_lcore_id(), d->iface->id);
	stats->cp_tx_packets += 1;
	stats->cp_tx_bytes += rte_pktmbuf_pkt_len(m);

	if (gr_config.log_packets)
		trace_log_packet(m, "cp tx", d->iface->name);

	if (gr_mbuf_is_traced(m))
		gr_mbuf_trace_finish(m);
end:
	if (!rte_pktmbuf_is_contiguous(m))
		rte_free(data);
	rte_pktmbuf_free(m);
}

static void iface_cp_poll(evutil_socket_t, short reason, void *ev_iface) {
	struct iface *iface = ev_iface;
	struct eth_input_mbuf_data *e;
	struct iface_stats *stats;
	struct rte_mbuf *mbuf;
	size_t read_len;
	size_t len;
	char *data;

	if (reason & EV_CLOSED) {
		LOG(ERR, "tap device %s deleted", iface->name);
		iface_destroy(iface->id);
		return;
	}

	mbuf = rte_pktmbuf_alloc(cp_pool);
	if (!mbuf) {
		LOG(ERR, "rte_pktmbuf_alloc %s", rte_strerror(rte_errno));
		goto err;
	}

	read_len = iface->mtu + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN;
	if ((data = rte_pktmbuf_append(mbuf, read_len)) == NULL) {
		LOG(ERR, "rte_pktmbuf_alloc %s", rte_strerror(rte_errno));
		goto err;
	}

	if ((len = read(iface->cp_fd, data, read_len)) <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		LOG(ERR, "read from tun device %s failed %s", iface->name, strerror(errno));
		goto err;
	}

	rte_pktmbuf_trim(mbuf, read_len - len);

	// packet sent from linux tun iface, no need to compute checksum;
	mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD;
	mbuf->packet_type = rte_net_get_ptype(mbuf, NULL, RTE_PTYPE_ALL_MASK);

	e = eth_input_mbuf_data(mbuf);
	e->iface = iface;
	e->domain = ETH_DOMAIN_LOOPBACK;

	stats = iface_get_stats(rte_lcore_id(), iface->id);
	stats->cp_rx_packets += 1;
	stats->cp_rx_bytes += rte_pktmbuf_pkt_len(mbuf);

	if (gr_config.log_packets)
		trace_log_packet(mbuf, "cp rx", iface->name);

	post_to_stack(port_output_id, mbuf);
	return;

err:
	rte_pktmbuf_free(mbuf);
}

static void cp_create(struct iface *iface) {
	struct iface_info_port *port = iface_info_port(iface);
	struct ifreq ifr;
	int ioctl_sock;
	int flags;

	memset(&ifr, 0, sizeof(struct ifreq));
	memccpy(ifr.ifr_name, iface->name, 0, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_ONE_QUEUE | IFF_NO_PI | IFF_MULTICAST;

	if ((ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		LOG(ERR, "socket(SOCK_DGRAM): %s", strerror(errno));
		goto err;
	}

	if ((iface->cp_fd = open(TUN_TAP_DEV_PATH, O_RDWR)) < 0) {
		LOG(ERR, "open(%s): %s", TUN_TAP_DEV_PATH, strerror(errno));
		goto err;
	}

	if (ioctl(iface->cp_fd, TUNSETIFF, &ifr) < 0) {
		LOG(ERR, "ioctl(TUNSETIFF): %s", strerror(errno));
		goto err;
	}

	flags = fcntl(iface->cp_fd, F_GETFL);
	if (flags == -1) {
		LOG(ERR, "fcntl(F_GETFL): %s", strerror(errno));
		goto err;
	}

	flags |= O_NONBLOCK;
	if (fcntl(iface->cp_fd, F_SETFL, flags) < 0) {
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

	memcpy(ifr.ifr_hwaddr.sa_data, port->mac.addr_bytes, sizeof(port->mac));
	if (ioctl(ioctl_sock, SIOCSIFHWADDR, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCGIFHWADDR) %s", strerror(errno));
		goto err;
	}

	if (ioctl(ioctl_sock, SIOCGIFINDEX, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCGIFINDEX) %s", strerror(errno));
		goto err;
	}
	iface->cp_id = ifr.ifr_ifindex;

	iface->cp_ev = event_new(
		ev_base,
		iface->cp_fd,
		EV_READ | EV_CLOSED | EV_PERSIST | EV_FINALIZE,
		iface_cp_poll,
		iface
	);

	if (iface->cp_ev == NULL || event_add(iface->cp_ev, NULL) < 0) {
		event_free(iface->cp_ev);
		goto err;
	}
	close(ioctl_sock);
	return;

err:
	//err_save = errno;
	if (iface->cp_fd > 0)
		close(iface->cp_fd);
	if (ioctl_sock > 0)
		close(ioctl_sock);
}

static void cp_delete(struct iface *iface) {
	event_free_finalize(0, iface->cp_ev, finalize_fd);
}

static void iface_event(uint32_t event, const void *obj) {
	struct iface *iface = (struct iface *)obj;
	// XXX: Create tun interface instead of TAP for non eth ifaces
	if (iface->type == GR_IFACE_TYPE_LOOPBACK || iface->type == GR_IFACE_TYPE_IPIP)
		return;

	switch (event) {
	case GR_EVENT_IFACE_POST_ADD:
		cp_create(iface);
		break;
	case GR_EVENT_IFACE_PRE_REMOVE:
		cp_delete(iface);
		break;
	}
}

static struct gr_event_subscription iface_event_handler = {
	.callback = iface_event,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IFACE_POST_ADD,
		GR_EVENT_IFACE_PRE_REMOVE,
	},
};

static void cp_module_init(struct event_base *base) {
	cp_pool = gr_pktmbuf_pool_get(SOCKET_ID_ANY, RTE_GRAPH_BURST_SIZE);
	if (!cp_pool)
		ABORT("pktmbuf_pool returned NULL");
	ev_base = base;
	port_output_id = gr_control_input_register_handler("port_output", true);
}

static void cp_module_fini(struct event_base *) {
	gr_pktmbuf_pool_release(cp_pool, RTE_GRAPH_BURST_SIZE);
}

static struct gr_module cp_module = {
	.name = "controlplane",
	.depends_on = "graph",
	.init = cp_module_init,
	.fini = cp_module_fini,
};

RTE_INIT(cp_constructor) {
	gr_register_module(&cp_module);
	gr_event_subscribe(&iface_event_handler);
}
