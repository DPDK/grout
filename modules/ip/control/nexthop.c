// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_clock.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
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
#include <string.h>
#include <sys/queue.h>

static control_input_t ip_output_node;

void nh4_unreachable_cb(void *obj, uintptr_t, const struct control_queue_drain *drain) {
	struct rte_mbuf *m = obj;
	struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
	ip4_addr_t dst = ip->dst_addr;
	struct nexthop_info_l3 *l3;
	struct nexthop *nh;

	nh = (struct nexthop *)ip_output_mbuf_data(m)->nh;

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

	if (l3->flags & GR_NH_F_LINK && dst != l3->ipv4) {
		// The resolved nexthop is associated with a "connected" route.
		// We currently do not have an explicit route entry for this
		// destination IP.
		struct nexthop *remote = nh4_lookup(nh->vrf_id, dst);

		if (remote == NULL) {
			// No existing nexthop for this IP, create one.
			remote = nexthop_new(
				&(struct gr_nexthop_base) {
					.type = GR_NH_T_L3,
					.origin = GR_NH_ORIGIN_INTERNAL,
					.vrf_id = nh->vrf_id,
					.iface_id = nh->iface_id,
				},
				&(struct gr_nexthop_info_l3) {
					.af = GR_AF_IP4,
					.ipv4 = dst,
				}
			);
			if (remote == NULL) {
				LOG(ERR, "cannot allocate nexthop: %s", strerror(errno));
				goto free;
			}
			// Create an associated /32 route so that next packets take it
			// in priority with a single route lookup.
			if (rib4_insert(nh->vrf_id, dst, 32, GR_NH_ORIGIN_INTERNAL, remote) < 0) {
				LOG(ERR, "failed to insert route: %s", strerror(errno));
				goto free;
			}
		}

		assert(remote->iface_id == nh->iface_id);
		nh = remote;
		l3 = nexthop_info_l3(remote);
	}

	if (l3->state == GR_NH_S_REACHABLE) {
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

	if (l3->held_pkts < nh_conf.max_held_pkts) {
		queue_mbuf_data(m)->next = NULL;
		if (l3->held_pkts_head == NULL)
			l3->held_pkts_head = m;
		else
			queue_mbuf_data(l3->held_pkts_tail)->next = m;
		l3->held_pkts_tail = m;
		l3->held_pkts++;
		if (l3->state != GR_NH_S_PENDING) {
			arp_output_request_solicit(nh);
			l3->state = GR_NH_S_PENDING;
		}
		return;
	} else {
		LOG(DEBUG, IP4_F " hold queue full", &dst);
	}
free:
	rte_pktmbuf_free(m);
}

static control_input_t arp_output_reply_node;

void arp_probe_input_cb(void *obj, uintptr_t, const struct control_queue_drain *drain) {
	struct nexthop_info_l3 *l3;
	const struct iface *iface;
	struct rte_mbuf *m = obj;
	struct rte_arp_hdr *arp;
	struct rte_mbuf *held;
	struct nexthop *nh;
	ip4_addr_t sip;

	arp = rte_pktmbuf_mtod(m, struct rte_arp_hdr *);
	iface = mbuf_data(m)->iface;

	// Check if packet references deleted interface.
	if (drain != NULL && drain->event == GR_EVENT_IFACE_REMOVE && iface == drain->obj)
		goto free;

	sip = arp->arp_data.arp_sip;
	nh = nh4_lookup(iface->vrf_id, sip);
	if (nh == NULL) {
		// We don't have an entry for the ARP request sender address yet.
		//
		// Create one now. If the sender has requested our mac address,
		// they will certainly contact us soon and it will save us an
		// ARP request.
		nh = nexthop_new(
			&(struct gr_nexthop_base) {
				.type = GR_NH_T_L3,
				.origin = GR_NH_ORIGIN_INTERNAL,
				.iface_id = iface->id,
				.vrf_id = iface->vrf_id,
			},
			&(struct gr_nexthop_info_l3) {
				.af = GR_AF_IP4,
				.ipv4 = sip,
			}
		);
		if (nh == NULL) {
			LOG(ERR, "ip4_nexthop_new: %s", strerror(errno));
			goto free;
		}
		// Add an internal /32 route to reference the newly created nexthop.
		if (rib4_insert(iface->vrf_id, sip, 32, GR_NH_ORIGIN_INTERNAL, nh) < 0) {
			LOG(ERR, "ip4_nexthop_insert: %s", strerror(errno));
			goto free;
		}
	}

	l3 = nexthop_info_l3(nh);

	// static next hops never need updating
	if (!(l3->flags & GR_NH_F_STATIC)) {
		// Refresh all fields.
		l3->last_reply = gr_clock_us();
		l3->state = GR_NH_S_REACHABLE;
		l3->ucast_probes = 0;
		l3->bcast_probes = 0;
		l3->mac = arp->arp_data.arp_sha;
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
	held = l3->held_pkts_head;
	while (held != NULL) {
		struct ip_output_mbuf_data *o;
		struct rte_mbuf *next;

		next = queue_mbuf_data(held)->next;
		o = ip_output_mbuf_data(held);
		o->nh = nh;
		o->iface = NULL;
		if (post_to_stack(ip_output_node, held) < 0) {
			LOG(ERR, "post_to_stack: %s", strerror(errno));
			rte_pktmbuf_free(held);
		}
		held = next;
	}
	l3->held_pkts_head = NULL;
	l3->held_pkts_tail = NULL;
	l3->held_pkts = 0;

free:
	rte_pktmbuf_free(m);
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

static struct nexthop_af_ops nh_ops = {
	.solicit = arp_output_request_solicit,
	.cleanup_routes = rib4_cleanup,
};

RTE_INIT(control_ip_init) {
	gr_register_module(&nh4_module);
	nexthop_af_ops_register(GR_AF_IP4, &nh_ops);
}
