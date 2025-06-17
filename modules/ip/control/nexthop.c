// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_clock.h>
#include <gr_control_input.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_ip4.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_queue.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_arp.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_mempool.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static control_input_t ip_output_node;

void nh4_unreachable_cb(struct rte_mbuf *m) {
	struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
	ip4_addr_t dst = ip->dst_addr;
	struct nexthop *nh;

	nh = rib4_lookup(control_output_mbuf_data(m)->iface->vrf_id, dst);
	if (nh == NULL)
		goto free; // route to dst has disappeared

	if (nh->flags & GR_NH_F_LINK && dst != nh->ipv4) {
		// The resolved nexthop is associated with a "connected" route.
		// We currently do not have an explicit route entry for this
		// destination IP.
		struct nexthop *remote = nh4_lookup(nh->vrf_id, dst);

		if (remote == NULL) {
			// No existing nexthop for this IP, create one.
			remote = nh4_new(nh->vrf_id, nh->iface_id, dst);
		}

		if (remote == NULL) {
			LOG(ERR, "cannot allocate nexthop: %s", strerror(errno));
			goto free;
		}
		if (remote->iface_id != nh->iface_id)
			ABORT(IP4_F " nexthop lookup gives wrong interface", &ip);

		// Create an associated /32 route so that next packets take it
		// in priority with a single route lookup.
		if (rib4_insert(nh->vrf_id, dst, 32, GR_RT_ORIGIN_INTERNAL, remote) < 0) {
			LOG(ERR, "failed to insert route: %s", strerror(errno));
			goto free;
		}
		nh = remote;
	}

	if (nh->flags & GR_NH_F_REACHABLE) {
		// The nexthop may have become reachable while the packet was
		// passed from the datapath to here. Re-send it to datapath.
		struct ip_output_mbuf_data *d = ip_output_mbuf_data(m);
		d->nh = nh;
		if (post_to_stack(ip_output_node, m) < 0) {
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
		if (!(nh->flags & GR_NH_F_PENDING)) {
			arp_output_request_solicit(nh);
			nh->flags |= GR_NH_F_PENDING;
		}
		return;
	} else {
		LOG(DEBUG, IP4_F " hold queue full", &dst);
	}
free:
	rte_pktmbuf_free(m);
}

static control_input_t arp_output_reply_node;

void arp_probe_input_cb(struct rte_mbuf *m) {
	const struct iface *iface;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *held;
	struct nexthop *nh;
	ip4_addr_t sip;

	arp = rte_pktmbuf_mtod(m, struct rte_arp_hdr *);
	iface = mbuf_data(m)->iface;

	sip = arp->arp_data.arp_sip;
	nh = nh4_lookup(iface->vrf_id, sip);
	if (nh == NULL) {
		// We don't have an entry for the ARP request sender address yet.
		//
		// Create one now. If the sender has requested our mac address,
		// they will certainly contact us soon and it will save us an
		// ARP request.
		if ((nh = nh4_new(iface->vrf_id, iface->id, sip)) == NULL) {
			LOG(ERR, "ip4_nexthop_new: %s", strerror(errno));
			goto free;
		}
		// Add an internal /32 route to reference the newly created nexthop.
		if (rib4_insert(iface->vrf_id, sip, 32, GR_RT_ORIGIN_INTERNAL, nh) < 0) {
			LOG(ERR, "ip4_nexthop_insert: %s", strerror(errno));
			goto free;
		}
	}

	// static next hops never need updating
	if (!(nh->flags & GR_NH_F_STATIC)) {
		// Refresh all fields.
		nh->last_reply = gr_clock_us();
		nh->iface_id = iface->id;
		nh->flags |= GR_NH_F_REACHABLE;
		nh->flags &= ~(GR_NH_F_STALE | GR_NH_F_PENDING | GR_NH_F_FAILED);
		nh->ucast_probes = 0;
		nh->bcast_probes = 0;
		nh->mac = arp->arp_data.arp_sha;
		gr_event_push(GR_EVENT_NEXTHOP_UPDATE, nh);
	}

	if (arp->arp_opcode == RTE_BE16(RTE_ARP_OP_REQUEST)) {
		// send a reply for our local ip
		struct nexthop *local = nh4_lookup(iface->vrf_id, arp->arp_data.arp_tip);
		struct arp_reply_mbuf_data *d = arp_reply_mbuf_data(m);
		d->local = local;
		d->iface = iface;
		if (post_to_stack(arp_output_reply_node, m) < 0) {
			LOG(ERR, "post_to_stack: %s", strerror(errno));
			goto free;
		}
		// prevent double free, mbuf has been re-consumed by datapath
		m = NULL;
	}

	// Flush all held packets.
	held = nh->held_pkts_head;
	while (held != NULL) {
		struct ip_output_mbuf_data *o;
		struct rte_mbuf *next;

		next = queue_mbuf_data(held)->next;
		o = ip_output_mbuf_data(held);
		o->nh = nh;
		o->iface = NULL;
		post_to_stack(ip_output_node, held);
		held = next;
	}
	nh->held_pkts_head = NULL;
	nh->held_pkts_tail = NULL;
	nh->held_pkts = 0;

free:
	rte_pktmbuf_free(m);
}

static int nh4_add(struct nexthop *nh) {
	return rib4_insert(nh->vrf_id, nh->ipv4, 32, GR_RT_ORIGIN_LINK, nh);
}

static void nh4_free(struct nexthop *nh) {
	rib4_delete(nh->vrf_id, nh->ipv4, 32);
	if (nh->ref_count > 0) {
		nh->flags &= ~(GR_NH_F_REACHABLE | GR_NH_F_PENDING | GR_NH_F_FAILED);
		memset(&nh->mac, 0, sizeof(nh->mac));
	}
}

static void nh4_init(struct event_base *) {
	ip_output_node = gr_control_input_register_handler("ip_output", true);
	arp_output_reply_node = gr_control_input_register_handler("arp_output_reply", true);
}

static struct gr_module nh4_module = {
	.name = "ipv4 nexthop",
	.depends_on = "graph",
	.init = nh4_init,
};

static struct nexthop_ops nh_ops = {
	.add = nh4_add,
	.solicit = arp_output_request_solicit,
	.free = nh4_free,
};

RTE_INIT(control_ip_init) {
	gr_register_module(&nh4_module);
	nexthop_ops_register(GR_NH_IPV4, &nh_ops);
}
