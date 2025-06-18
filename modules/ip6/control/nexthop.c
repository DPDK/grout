// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_clock.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
#include <gr_event.h>
#include <gr_icmp6.h>
#include <gr_iface.h>
#include <gr_ip6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_queue.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ip6.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static control_input_t ip6_output_node;

void nh6_unreachable_cb(struct rte_mbuf *m) {
	struct rte_ipv6_hdr *ip = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
	const struct rte_ipv6_addr *dst = &ip->dst_addr;
	struct nexthop *nh;

	nh = rib6_lookup(mbuf_data(m)->iface->vrf_id, mbuf_data(m)->iface->id, dst);
	if (nh == NULL)
		goto free; // route to dst has disappeared

	if (nh->flags & GR_NH_F_LINK && !rte_ipv6_addr_eq(dst, &nh->ipv6)) {
		// The resolved nexthop is associated with a "connected" route.
		// We currently do not have an explicit route entry for this
		// destination IP.
		struct nexthop *remote = nh6_lookup(nh->vrf_id, mbuf_data(m)->iface->id, dst);

		if (remote == NULL) {
			// No existing nexthop for this IP, create one.
			remote = nh6_new(nh->vrf_id, nh->iface_id, dst);
		}

		if (remote == NULL) {
			LOG(ERR, "cannot allocate nexthop: %s", strerror(errno));
			goto free;
		}
		if (remote->iface_id != nh->iface_id)
			ABORT(IP6_F " nexthop lookup gives wrong interface", &ip);

		// Create an associated /128 route so that next packets take it
		// in priority with a single route lookup.
		int ret = rib6_insert(
			nh->vrf_id,
			nh->iface_id,
			dst,
			RTE_IPV6_MAX_DEPTH,
			GR_RT_ORIGIN_INTERNAL,
			remote
		);
		if (ret < 0) {
			LOG(ERR, "failed to insert route: %s", strerror(errno));
			goto free;
		}
		nh = remote;
	}

	if (nh->state == GR_NH_S_REACHABLE) {
		// The nexthop may have become reachable while the packet was
		// passed from the datapath to here. Re-send it to datapath.
		struct ip6_output_mbuf_data *d = ip6_output_mbuf_data(m);
		d->nh = nh;
		if (post_to_stack(ip6_output_node, m) < 0) {
			LOG(ERR, "post_to_stack: %s", strerror(errno));
			goto free;
		}
		return;
	}

	if (nh->held_pkts < nh_conf.max_held_pkts) {
		queue_mbuf_data(m)->next = NULL;
		if (nh->held_pkts_head == NULL)
			nh->held_pkts_head = m;
		else
			queue_mbuf_data(nh->held_pkts_tail)->next = m;
		nh->held_pkts_tail = m;
		nh->held_pkts++;
		if (nh->state != GR_NH_S_PENDING) {
			nh6_solicit(nh);
			nh->state = GR_NH_S_PENDING;
		}
		return;
	} else {
		LOG(DEBUG, IP4_F " hold queue full", &dst);
	}
free:
	rte_pktmbuf_free(m);
}

static control_input_t ndp_na_output_node;

void ndp_probe_input_cb(struct rte_mbuf *m) {
	const struct icmp6 *icmp6 = rte_pktmbuf_mtod(m, const struct icmp6 *);
	const struct rte_ipv6_addr *remote, *local;
	const struct ip6_local_mbuf_data *d;
	const struct icmp6_neigh_solicit *ns;
	const struct icmp6_neigh_advert *na;
	icmp6_opt_found_t lladdr_found;
	const struct iface *iface;
	struct rte_ether_addr mac;
	struct nexthop *nh = NULL;

	d = (const struct ip6_local_mbuf_data *)control_output_mbuf_data(m)->cb_data;
	iface = control_output_mbuf_data(m)->iface;

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

	if (!rte_ipv6_addr_is_unspec(remote) && !rte_ipv6_addr_is_mcast(remote)) {
		nh = nh6_lookup(iface->vrf_id, iface->id, remote);
		if (nh == NULL) {
			// We don't have an entry for the probe sender address yet.
			//
			// Create one now. If the sender has requested our mac address, they
			// will certainly contact us soon and it will save us an NDP solicitation.
			if ((nh = nh6_new(iface->vrf_id, iface->id, remote)) == NULL) {
				LOG(ERR, "ip6_nexthop_new: %s", strerror(errno));
				goto free;
			}

			// Add an internal /128 route to reference the newly created nexthop.
			int ret = rib6_insert(
				iface->vrf_id,
				iface->id,
				remote,
				RTE_IPV6_MAX_DEPTH,
				GR_RT_ORIGIN_INTERNAL,
				nh
			);
			if (ret < 0) {
				LOG(ERR, "ip6_route_insert: %s", strerror(errno));
				goto free;
			}
		}
	}

	if (nh && !(nh->flags & GR_NH_F_STATIC) && lladdr_found == ICMP6_OPT_FOUND) {
		// Refresh all fields.
		nh->last_reply = gr_clock_us();
		nh->iface_id = iface->id;
		nh->state = GR_NH_S_REACHABLE;
		nh->ucast_probes = 0;
		nh->bcast_probes = 0;
		nh->mac = mac;
		gr_event_push(GR_EVENT_NEXTHOP_UPDATE, nh);
	}

	if (icmp6->type == ICMP6_TYPE_NEIGH_SOLICIT && local != NULL) {
		// send a reply for our local ip
		struct ndp_na_output_mbuf_data *d = ndp_na_output_mbuf_data(m);
		d->local = nh6_lookup(iface->vrf_id, iface->id, local);
		d->remote = nh;
		d->iface = iface;
		if (post_to_stack(ndp_na_output_node, m) < 0) {
			LOG(ERR, "post_to_stack: %s", strerror(errno));
			goto free;
		}
		// prevent double free, mbuf has been re-consumed by datapath
		m = NULL;
	}

	// Flush all held packets.
	struct rte_mbuf *held = nh->held_pkts_head;
	while (held != NULL) {
		struct ip6_output_mbuf_data *o;
		struct rte_mbuf *next;

		next = queue_mbuf_data(held)->next;
		o = ip6_output_mbuf_data(held);
		o->nh = nh;
		o->iface = NULL;
		post_to_stack(ip6_output_node, held);
		held = next;
	}
	nh->held_pkts_head = NULL;
	nh->held_pkts_tail = NULL;
	nh->held_pkts = 0;
free:
	rte_pktmbuf_free(m);
}

static int nh6_add(struct nexthop *nh) {
	return rib6_insert(nh->vrf_id, nh->iface_id, &nh->ipv6, 128, GR_RT_ORIGIN_LINK, nh);
}

static void nh6_free(struct nexthop *nh) {
	rib6_delete(nh->vrf_id, nh->iface_id, &nh->ipv6, RTE_IPV6_MAX_DEPTH);
	if (nh->ref_count > 0) {
		nh->state = GR_NH_S_NEW;
		memset(&nh->mac, 0, sizeof(nh->mac));
	}
}

static void nh6_init(struct event_base *) {
	ip6_output_node = gr_control_input_register_handler("ip6_output", true);
	ndp_na_output_node = gr_control_input_register_handler("ndp_na_output", true);
}

static struct gr_module nh6_module = {
	.name = "ipv6 nexthop",
	.depends_on = "graph",
	.init = nh6_init,
};

static struct nexthop_ops nh_ops = {
	.add = nh6_add,
	.solicit = nh6_solicit,
	.free = nh6_free,
};

RTE_INIT(control_ip_init) {
	gr_register_module(&nh6_module);
	nexthop_ops_register(GR_NH_IPV6, &nh_ops);
}
