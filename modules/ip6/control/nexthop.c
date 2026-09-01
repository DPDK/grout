// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "clock.h"
#include "event.h"
#include "icmp6.h"
#include "iface.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "l3.h"
#include "log.h"

#include <gr_net_types.h>

#include <event2/event.h>
#include <rte_ether.h>
#include <rte_ip6.h>

#include <errno.h>
#include <string.h>
#include <sys/queue.h>

LOG_TYPE("nexthop");

static int ip6_resubmit_cb(struct rte_mbuf *m, struct nexthop *nh) {
	struct l3_mbuf_data *d = l3_mbuf_data(m);
	d->nh = nh;
	d->iface = NULL;
	if (ip6_output_send(m) < 0) {
		LOG(ERR, "post_to_stack: %s", strerror(errno));
		return -errno;
	}
	return 0;
}

static void nh6_resolve_cb(void *obj, uintptr_t, const struct control_queue_drain *drain) {
	const struct rte_ipv6_addr *dst;
	struct nexthop_info_l3 *l3;
	struct rte_mbuf *m = obj;
	struct rte_ipv6_hdr *ip;
	struct nexthop *nh;

	nh = (struct nexthop *)l3_mbuf_data(m)->nh;

	if (drain != NULL) {
		// Check if packet references deleted object.
		switch (drain->event) {
		case GR_EVENT_IFACE_REMOVE:
			if (mbuf_data(m)->iface == drain->obj)
				goto free;
			break;
		case GR_EVENT_NEXTHOP_DELETE:
			if (nh == drain->obj)
				goto free;
			break;
		}
	}

	l3 = nexthop_info_l3(nh);

	if (!(m->packet_type & RTE_PTYPE_L3_IPV6))
		goto hold;

	ip = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
	dst = &ip->dst_addr;

	if (l3->flags & GR_NH_F_LINK && !rte_ipv6_addr_eq(dst, &l3->ipv6)) {
		// The resolved nexthop is associated with a "connected" route.
		// We currently do not have an explicit route entry for this
		// destination IP.
		struct nexthop *remote = nh6_lookup(nh->vrf_id, mbuf_data(m)->iface->id, dst);

		if (remote == NULL) {
			// No existing nexthop for this IP, create one.
			remote = nexthop_new(
				&(struct gr_nexthop_base) {
					.type = GR_NH_T_L3,
					.iface_id = nh->iface_id,
					.vrf_id = nh->vrf_id,
					.origin = GR_NH_ORIGIN_LEARN,
				},
				&(struct gr_nexthop_info_l3) {
					.af = GR_AF_IP6,
					.ipv6 = *dst,
					.flags = GR_NH_F_NEIGH,
				}
			);
			if (remote == NULL) {
				LOG(ERR, "cannot allocate nexthop: %s", strerror(errno));
				goto free;
			}
			// Create an associated /128 route so that next packets take it
			// in priority with a single route lookup.
			int ret = rib6_insert(
				nh->vrf_id,
				nh->iface_id,
				dst,
				RTE_IPV6_MAX_DEPTH,
				GR_NH_ORIGIN_INTERNAL,
				remote
			);
			if (ret < 0) {
				nexthop_decref(remote);
				LOG(ERR, "failed to insert route: %s", strerror(errno));
				goto free;
			}
		} else if (remote->iface_id != nh->iface_id) {
			// remote may live on a different interface than the connected
			// route. In EVPN L3VNI VRFs, a host inside a connected subnet
			// can be reachable through the VXLAN interface while the subnet
			// itself is connected on the bridge SVI.
			LOG(DEBUG,
			    "remote " IP6_F " (iface=%u), "
			    "connected route " IP6_F "/%hhu (iface=%u)",
			    &nexthop_info_l3(remote)->ipv6,
			    remote->iface_id,
			    &l3->ipv6,
			    l3->prefixlen,
			    nh->iface_id);
		}

		nh = remote;
		l3 = nexthop_info_l3(remote);
	}

hold:
	if (l3->state == GR_NH_S_REACHABLE) {
		// The nexthop may have become reachable while the packet was
		// passed from the datapath to here. Re-send it to datapath.
		const struct nexthop_af_ops *ops = nexthop_af_ops_from_mbuf(m);
		assert(ops != NULL);
		if (ops->resubmit(m, nh) < 0) {
			goto free;
		}
		return;
	}

	if (nexthop_l3_hold_queue_add(nh, m) == 0) {
		if (l3->state != GR_NH_S_PENDING) {
			nh6_solicit(nh);
			l3->state = GR_NH_S_PENDING;
		}
		return;
	} else {
		LOG(DEBUG, IP6_F " hold queue: %s", &l3->ipv6, strerror(errno));
	}
free:
	rte_pktmbuf_free(m);
}

void ndp_probe_input_cb(void *obj, uintptr_t, const struct control_queue_drain *drain) {
	struct rte_mbuf *m = obj;
	const struct icmp6 *icmp6 = rte_pktmbuf_mtod(m, const struct icmp6 *);
	const struct rte_ipv6_addr *remote, *local;
	const struct ip6_local_mbuf_data *d;
	const struct icmp6_neigh_solicit *ns;
	const struct icmp6_neigh_advert *na;
	icmp6_opt_found_t lladdr_found;
	const struct iface *iface;
	struct rte_ether_addr mac;
	struct nexthop *nh = NULL;

	d = ip6_local_mbuf_data(m);
	iface = mbuf_data(m)->iface;
	memset(&mac, 0, sizeof(mac));

	// Check if packet references deleted interface.
	if (drain != NULL && drain->event == GR_EVENT_IFACE_REMOVE && iface == drain->obj)
		goto free;

	switch (icmp6->type) {
	case ICMP6_TYPE_NEIGH_SOLICIT:
		ns = PAYLOAD(icmp6);
		local = &ns->target;
		remote = &d->src;
		lladdr_found = icmp6_get_opt(
			m, sizeof(*icmp6) + sizeof(*ns), ICMP6_OPT_SRC_LLADDR, &mac
		);
		break;
	case ICMP6_TYPE_NEIGH_ADVERT:
		na = PAYLOAD(icmp6);
		local = NULL;
		remote = &na->target;
		lladdr_found = icmp6_get_opt(
			m, sizeof(*icmp6) + sizeof(*na), ICMP6_OPT_TARGET_LLADDR, &mac
		);
		break;
	default:
		goto free;
	}

	if (lladdr_found == ICMP6_OPT_INVAL)
		goto free;

	if (rte_ipv6_addr_is_unspec(remote) || rte_ipv6_addr_is_mcast(remote))
		goto free;

	nh = nh6_lookup(iface->vrf_id, iface->id, remote);
	if (nh == NULL) {
		// We don't have an entry for the probe sender address yet.
		//
		// Create one now. If the sender has requested our mac address, they
		// will certainly contact us soon and it will save us an NDP solicitation.
		nh = nexthop_new(
			&(struct gr_nexthop_base) {
				.type = GR_NH_T_L3,
				.iface_id = iface->id,
				.vrf_id = iface->vrf_id,
				.origin = GR_NH_ORIGIN_LEARN,
			},
			&(struct gr_nexthop_info_l3) {
				.af = GR_AF_IP6,
				.ipv6 = *remote,
				.mac = mac,
				.flags = GR_NH_F_NEIGH,
			}
		);
		if (nh == NULL) {
			LOG(ERR, "ip6_nexthop_new: %s", strerror(errno));
			goto free;
		}

		// Add an internal /128 route to reference the newly created nexthop.
		int ret = rib6_insert(
			iface->vrf_id,
			iface->id,
			remote,
			RTE_IPV6_MAX_DEPTH,
			GR_NH_ORIGIN_INTERNAL,
			nh
		);
		if (ret < 0) {
			nexthop_decref(nh);
			LOG(ERR, "ip6_route_insert: %s", strerror(errno));
			goto free;
		}
	} else if (lladdr_found == ICMP6_OPT_FOUND) {
		// Refresh all fields.
		struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
		l3->last_reply = clock_ns();
		l3->state = GR_NH_S_REACHABLE;
		l3->ucast_probes = 0;
		l3->bcast_probes = 0;
		l3->mac = mac;
		if (nh->origin != GR_NH_ORIGIN_INTERNAL)
			event_push(GR_EVENT_NEXTHOP_UPDATE, nh);
	}

	if (icmp6->type == ICMP6_TYPE_NEIGH_SOLICIT && local != NULL) {
		// send a reply for our local ip
		const struct nexthop *local_nh = nh6_lookup(iface->vrf_id, iface->id, local);
		if (local_nh == NULL) {
			LOG(INFO, "local address " IP6_F " has disappeared", local);
			goto free;
		}
		if (nh6_advertise(local_nh, nh) < 0) {
			LOG(ERR, "nh6_advertise: %s", strerror(errno));
			goto free;
		}
	}

	// Flush all held packets.
	nexthop_l3_hold_queue_foreach (held, nh) {
		const struct nexthop_af_ops *ops;

		ops = nexthop_af_ops_from_mbuf(held);
		assert(ops != NULL);
		if (ops->resubmit(held, nh) < 0)
			rte_pktmbuf_free(held);
	}
	nexthop_l3_hold_queue_reset(nh);

free:
	rte_pktmbuf_free(m);
}

static struct nexthop_af_ops nh_ops = {
	.resolve = nh6_resolve_cb,
	.solicit = nh6_solicit,
	.cleanup_routes = rib6_cleanup,
	.resubmit = ip6_resubmit_cb,
};

RTE_INIT(control_ip_init) {
	nexthop_af_ops_register(GR_AF_IP6, &nh_ops);
}
