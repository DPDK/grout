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

static struct api_out nh4_add(const void *request, void ** /*response*/) {
	const struct gr_ip4_nh_add_req *req = request;
	struct nexthop *nh;
	int ret;

	if (req->nh.ipv4 == 0)
		return api_out(EINVAL, 0);
	if (req->nh.vrf_id >= MAX_VRFS)
		return api_out(EOVERFLOW, 0);
	if (iface_from_id(req->nh.iface_id) == NULL)
		return api_out(errno, 0);

	if ((nh = nh4_lookup(req->nh.vrf_id, req->nh.ipv4)) != NULL) {
		if (req->exist_ok && req->nh.iface_id == nh->iface_id
		    && rte_is_same_ether_addr(&req->nh.mac, &nh->mac))
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	if ((nh = nh4_new(req->nh.vrf_id, req->nh.iface_id, req->nh.ipv4)) == NULL)
		return api_out(errno, 0);

	nh->mac = req->nh.mac;
	nh->flags = GR_NH_F_STATIC | GR_NH_F_REACHABLE;
	ret = rib4_insert(nh->vrf_id, nh->ipv4, 32, GR_RT_ORIGIN_LINK, nh);

	return api_out(-ret, 0);
}

static struct api_out nh4_del(const void *request, void ** /*response*/) {
	const struct gr_ip4_nh_del_req *req = request;
	struct nexthop *nh;

	if (req->vrf_id >= MAX_VRFS)
		return api_out(EOVERFLOW, 0);

	if ((nh = nh4_lookup(req->vrf_id, req->host)) == NULL) {
		if (errno == ENOENT && req->missing_ok)
			return api_out(0, 0);
		return api_out(errno, 0);
	}
	if ((nh->flags & (GR_NH_F_LOCAL | GR_NH_F_LINK | GR_NH_F_GATEWAY)) || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	// this also does ip4_nexthop_decref(), freeing the next hop
	if (rib4_delete(req->vrf_id, req->host, 32) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

struct list_context {
	uint16_t vrf_id;
	struct gr_nexthop *nh;
};

static void nh_list_cb(struct nexthop *nh, void *priv) {
	struct list_context *ctx = priv;

	if (nh->type != GR_NH_IPV4 || (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX))
		return;

	gr_vec_add(ctx->nh, nh->base);
}

static struct api_out nh4_list(const void *request, void **response) {
	const struct gr_ip4_nh_list_req *req = request;
	struct list_context ctx = {.vrf_id = req->vrf_id, .nh = NULL};
	struct gr_ip4_nh_list_resp *resp = NULL;
	size_t len;

	nexthop_iter(nh_list_cb, &ctx);

	len = sizeof(*resp) + gr_vec_len(ctx.nh) * sizeof(*ctx.nh);
	if ((resp = calloc(1, len)) == NULL) {
		gr_vec_free(ctx.nh);
		return api_out(ENOMEM, 0);
	}

	resp->n_nhs = gr_vec_len(ctx.nh);
	if (ctx.nh != NULL)
		memcpy(resp->nhs, ctx.nh, resp->n_nhs * sizeof(resp->nhs[0]));
	gr_vec_free(ctx.nh);
	*response = resp;

	return api_out(0, len);
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

static struct gr_api_handler nh4_add_handler = {
	.name = "ipv4 nexthop add",
	.request_type = GR_IP4_NH_ADD,
	.callback = nh4_add,
};
static struct gr_api_handler nh4_del_handler = {
	.name = "ipv4 nexthop del",
	.request_type = GR_IP4_NH_DEL,
	.callback = nh4_del,
};
static struct gr_api_handler nh4_list_handler = {
	.name = "ipv4 nexthop list",
	.request_type = GR_IP4_NH_LIST,
	.callback = nh4_list,
};

static struct gr_module nh4_module = {
	.name = "ipv4 nexthop",
	.depends_on = "graph",
	.init = nh4_init,
};

static struct nexthop_ops nh_ops = {
	.solicit = arp_output_request_solicit,
	.free = nh4_free,
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&nh4_add_handler);
	gr_register_api_handler(&nh4_del_handler);
	gr_register_api_handler(&nh4_list_handler);
	gr_register_module(&nh4_module);
	nexthop_ops_register(GR_NH_IPV4, &nh_ops);
}
