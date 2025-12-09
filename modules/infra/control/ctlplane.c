// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include "ctlplane.h"

#include <gr_bond.h>
#include <gr_config.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
#include <gr_eth.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_mempool.h>
#include <gr_module.h>
#include <gr_netlink.h>
#include <gr_nh_control.h>
#include <gr_port.h>
#include <gr_vlan.h>

#include <event2/event.h>
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
#include <sys/ioctl.h>

#define TUN_TAP_DEV_PATH "/dev/net/tun"

#define IFALIASZ 256 // Defined in linux/if.h, conflicting with net/if.h

static struct rte_mempool *cp_pool;
static struct event_base *ev_base;

static control_input_t port_output_id;

static void finalize_fd(struct event *ev, void * /*priv*/) {
	int fd = event_get_fd(ev);
	if (fd >= 0)
		close(fd);
}

void iface_cp_tx(struct rte_mbuf *m, const struct control_output_drain *drain) {
	struct mbuf_data *d = mbuf_data(m);
	struct iface_stats *stats;
	char *data = NULL;

	// Check if packet references deleted interface.
	if (drain != NULL && drain->event == GR_EVENT_IFACE_REMOVE && d->iface == drain->obj)
		goto end;

	if (d->iface->cp_fd == 0)
		goto end;

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
		if (errno == EBADF) {
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
	struct rte_ether_addr src, dst;
	struct iface_stats *stats;
	struct rte_ether_hdr *eth;
	struct rte_vlan_hdr *vlan;
	struct rte_mbuf *mbuf;
	rte_be16_t ether_type;
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
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			LOG(ERR, "read from tap device %s failed %s", iface->name, strerror(errno));
		goto err;
	}

	rte_pktmbuf_trim(mbuf, read_len - len);

	// packet sent from linux tun iface, no need to compute checksum;
	mbuf->ol_flags = RTE_MBUF_F_RX_IP_CKSUM_GOOD;
	mbuf->packet_type = rte_net_get_ptype(mbuf, NULL, RTE_PTYPE_ALL_MASK);

	eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

	// Rewrite dst mac as the flag NO_ARP is set on the ctlplane
	if (rte_is_multicast_ether_addr(&eth->dst_addr) == 0) {
		struct nexthop *nh = NULL;
		if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
			const struct rte_ipv4_hdr *ip;
			ip = rte_pktmbuf_mtod_offset(
				mbuf, const struct rte_ipv4_hdr *, sizeof(*eth)
			);
			if (ip)
				nh = nexthop_lookup(
					AF_INET, iface->vrf_id, iface->id, &ip->dst_addr
				);
		} else if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_IPV6)) {
			const struct rte_ipv6_hdr *ip;
			ip = rte_pktmbuf_mtod_offset(
				mbuf, const struct rte_ipv6_hdr *, sizeof(*eth)
			);
			if (ip)
				nh = nexthop_lookup(
					AF_INET6, iface->vrf_id, iface->id, &ip->dst_addr
				);
		}
		if (nh && nh->type == GR_NH_T_L3)
			eth->dst_addr = nexthop_info_l3(nh)->mac;
	}

	if (iface->type == GR_IFACE_TYPE_VLAN) {
		// For vlan interfaces, we have to insert ourselves the vlan header
		// as Linux has no knowledge of its existence.
		src = eth->src_addr;
		dst = eth->dst_addr;
		ether_type = eth->ether_type;
		rte_pktmbuf_adj(mbuf, sizeof(*eth));

		vlan = gr_mbuf_prepend(mbuf, vlan);
		if (vlan == NULL) {
			LOG(ERR, "ctlplane vlan_hdr insertion: no headroom");
			goto err;
		}

		vlan->vlan_tci = rte_cpu_to_be_16(iface_info_vlan(iface)->vlan_id);
		vlan->eth_proto = ether_type;

		eth = gr_mbuf_prepend(mbuf, eth);
		if (eth == NULL) {
			LOG(ERR, "ctlplane ether_hdr insertion: no headroom");
			goto err;
		}
		eth->src_addr = src;
		eth->dst_addr = dst;
		eth->ether_type = RTE_BE16(RTE_ETHER_TYPE_VLAN);

		const uint32_t parent_id = iface_info_vlan(iface)->parent_id;
		iface = iface_from_id(parent_id);
		if (iface == NULL) {
			LOG(ERR, "iface_from_id: no iface for id %u", parent_id);
			goto err;
		}
	} else if (iface->type == GR_IFACE_TYPE_BOND) {
		// For bond interface, find either the active interface
		// or the first active member (for LACP)
		struct iface_info_bond *b = iface_info_bond(iface);
		struct iface *child_iface = NULL;
		if (b->mode == GR_BOND_MODE_ACTIVE_BACKUP) {
			if (b->n_members == 0 || b->active_member >= b->n_members)
				goto err;
			child_iface = (struct iface *)b->members[b->active_member].iface;
		} else if (b->mode == GR_BOND_MODE_LACP) {
			for (uint8_t i = 0; i < b->n_members; i++) {
				struct bond_member *member = &b->members[i];
				if (member->active) {
					child_iface = (struct iface *)member->iface;
					break;
				}
			}
		} else {
			ABORT("unknown bond mode");
		}
		if (child_iface == NULL) {
			LOG(ERR, "No active member in bond %s", iface->name);
			goto err;
		}
		iface = child_iface;
	}
	mbuf_data(mbuf)->iface = iface;

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
	char ifalias[IFALIASZ];
	struct ifreq ifr;
	int ioctl_sock;
	int flags;

	memset(&ifr, 0, sizeof(struct ifreq));
	memccpy(ifr.ifr_name, iface->name, 0, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_MULTICAST;

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

	ifr.ifr_flags |= IFF_NOARP;
	if (ioctl(ioctl_sock, SIOCSIFFLAGS, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCSIFFLAGS): %s", strerror(errno));
		goto err;
	}

	if (ioctl(ioctl_sock, SIOCGIFINDEX, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCGIFINDEX) %s", strerror(errno));
		goto err;
	}
	iface->cp_id = ifr.ifr_ifindex;

	snprintf(ifalias, IFALIASZ, "Grout control plane interface");
	netlink_set_ifalias(iface->name, ifalias);

	iface->cp_ev = event_new(
		ev_base,
		iface->cp_fd,
		EV_READ | EV_CLOSED | EV_PERSIST | EV_FINALIZE,
		iface_cp_poll,
		iface
	);

	if (iface->cp_ev == NULL || event_add(iface->cp_ev, NULL) < 0) {
		if (iface->cp_ev)
			event_free(iface->cp_ev);
		iface->cp_ev = NULL;
		goto err;
	}
	close(ioctl_sock);
	return;

err:
	if (iface->cp_fd > 0)
		close(iface->cp_fd);
	if (ioctl_sock > 0)
		close(ioctl_sock);
}

static void cp_delete(struct iface *iface) {
	if (iface->cp_ev)
		event_free_finalize(0, iface->cp_ev, finalize_fd);
}

static void cp_set_carrier(struct iface *iface) {
#ifdef TUNSETCARRIER
	int carrier = iface->flags & GR_IFACE_S_RUNNING ? 1 : 0;
	if (ioctl(iface->cp_fd, TUNSETCARRIER, &carrier) < 0) {
		LOG(ERR, "ioctl(TUNSETCARRIER): %s", strerror(errno));
	}
#else
	(void)iface;
#endif
}

static void cp_set_speed(struct iface *iface) {
	struct ethtool_link_settings *els;
	struct ifreq ifr = {0};
	char buf[512] = {0};
	int ioctl_sock;

	memccpy(ifr.ifr_name, iface->name, 0, IFNAMSIZ);
	els = (struct ethtool_link_settings *)buf;

	if ((ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		LOG(ERR, "socket(SOCK_DGRAM): %s", strerror(errno));
		goto err;
	}

	ifr.ifr_data = (caddr_t)els;
	els->cmd = ETHTOOL_GLINKSETTINGS;
	if (ioctl(ioctl_sock, SIOCETHTOOL, &ifr) < 0) {
		LOG(ERR, "ETHTOOL_GLINKSETTINGS: %s", strerror(errno));
		goto err;
	}
	els->link_mode_masks_nwords = -els->link_mode_masks_nwords;
	if (ioctl(ioctl_sock, SIOCETHTOOL, &ifr) < 0) {
		LOG(ERR, "ETHTOOL_GLINKSETTINGS: %s", strerror(errno));
		goto err;
	}

	els->speed = iface->speed;
	els->duplex = DUPLEX_FULL;
	els->autoneg = AUTONEG_DISABLE;
	els->cmd = ETHTOOL_SLINKSETTINGS;

	if (ioctl(ioctl_sock, SIOCETHTOOL, &ifr) < 0) {
		LOG(ERR, "ETHTOOL_SLINKSETTINGS: %s", strerror(errno));
		goto err;
	}

err:
	if (ioctl_sock > 0)
		close(ioctl_sock);
}

static void cp_update(struct iface *iface) {
	struct rte_ether_addr mac;
	struct ifreq ifr = {0};
	int ioctl_sock;

	if ((ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		LOG(ERR, "socket(SOCK_DGRAM): %s", strerror(errno));
		goto err;
	}

	memccpy(ifr.ifr_name, iface->name, 0, IFNAMSIZ);
	ifr.ifr_mtu = iface->mtu;

	if (ioctl(ioctl_sock, SIOCSIFMTU, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCSIFMTU) %s", strerror(errno));
		goto err;
	}

	if (ioctl(ioctl_sock, SIOCGIFHWADDR, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCGIFHWADDR) %s", strerror(errno));
		goto err;
	}
	iface_get_eth_addr(iface->id, &mac);
	memcpy(ifr.ifr_hwaddr.sa_data, mac.addr_bytes, sizeof(mac));
	if (ioctl(ioctl_sock, SIOCSIFHWADDR, &ifr) < 0) {
		LOG(ERR, "ioctl(SIOCSIFHWADDR) %s", strerror(errno));
		goto err;
	}

err:
	if (ioctl_sock > 0)
		close(ioctl_sock);
}

static void iface_event(uint32_t event, const void *obj) {
	struct iface *iface = (struct iface *)obj;

	switch (iface->type) {
	case GR_IFACE_TYPE_PORT:
	case GR_IFACE_TYPE_VLAN:
	case GR_IFACE_TYPE_BOND:
		break;
	default:
		return;
	}

	switch (event) {
	case GR_EVENT_IFACE_ADD:
		cp_create(iface);
		// fallthrough
	case GR_EVENT_IFACE_POST_RECONFIG:
		cp_update(iface);
		break;
	case GR_EVENT_IFACE_REMOVE:
		cp_delete(iface);
		break;
	case GR_EVENT_IFACE_STATUS_UP:
		cp_set_speed(iface);
		cp_set_carrier(iface);
		netlink_link_set_admin_state(iface->name, true);
		break;
	case GR_EVENT_IFACE_STATUS_DOWN:
		cp_set_carrier(iface);
		netlink_link_set_admin_state(iface->name, false);
		break;
	}
}

static struct gr_event_subscription iface_event_handler = {
	.callback = iface_event,
	.ev_count = 5,
	.ev_types = {
		GR_EVENT_IFACE_ADD,
		GR_EVENT_IFACE_REMOVE,
		GR_EVENT_IFACE_STATUS_UP,
		GR_EVENT_IFACE_STATUS_DOWN,
		GR_EVENT_IFACE_POST_RECONFIG,
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
