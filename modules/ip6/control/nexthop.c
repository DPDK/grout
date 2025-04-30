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
#include <rte_mempool.h>

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

	if (nh->flags & GR_NH_F_REACHABLE) {
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
		if (!(nh->flags & GR_NH_F_PENDING)) {
			nh6_solicit(nh);
			nh->flags |= GR_NH_F_PENDING;
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
	const struct iface *iface;
	struct rte_ether_addr mac;
	struct nexthop *nh = NULL;
	bool lladdr_found;

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

	if (nh && !(nh->flags & GR_NH_F_STATIC) && lladdr_found) {
		// Refresh all fields.
		nh->last_reply = gr_clock_us();
		nh->iface_id = iface->id;
		nh->flags |= GR_NH_F_REACHABLE;
		nh->flags &= ~(GR_NH_F_STALE | GR_NH_F_PENDING | GR_NH_F_FAILED);
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

static struct api_out nh6_add(const void *request, void ** /*response*/) {
	const struct gr_ip6_nh_add_req *req = request;
	struct nexthop *nh;
	int ret;

	if (rte_ipv6_addr_is_unspec(&req->nh.ipv6) || rte_ipv6_addr_is_mcast(&req->nh.ipv6))
		return api_out(EINVAL, 0);
	if (req->nh.vrf_id >= MAX_VRFS)
		return api_out(EOVERFLOW, 0);
	if (iface_from_id(req->nh.iface_id) == NULL)
		return api_out(errno, 0);

	if ((nh = nh6_lookup(req->nh.vrf_id, req->nh.iface_id, &req->nh.ipv6)) != NULL) {
		if (req->exist_ok && req->nh.iface_id == nh->iface_id
		    && rte_is_same_ether_addr(&req->nh.mac, &nh->mac))
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	if ((nh = nh6_new(req->nh.vrf_id, req->nh.iface_id, &req->nh.ipv6)) == NULL)
		return api_out(errno, 0);

	nh->mac = req->nh.mac;
	nh->flags = GR_NH_F_STATIC | GR_NH_F_REACHABLE;
	ret = rib6_insert(
		nh->vrf_id, nh->iface_id, &nh->ipv6, RTE_IPV6_MAX_DEPTH, GR_RT_ORIGIN_LINK, nh
	);

	return api_out(-ret, 0);
}

static struct api_out nh6_del(const void *request, void ** /*response*/) {
	const struct gr_ip6_nh_del_req *req = request;
	struct nexthop *nh;

	if (req->vrf_id >= MAX_VRFS)
		return api_out(EOVERFLOW, 0);

	if ((nh = nh6_lookup(req->vrf_id, GR_IFACE_ID_UNDEF, &req->host)) == NULL) {
		if (errno == ENOENT && req->missing_ok)
			return api_out(0, 0);
		return api_out(errno, 0);
	}
	if ((nh->flags & (GR_NH_F_LOCAL | GR_NH_F_LINK | GR_NH_F_GATEWAY)) || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	// this also does nh6_decref(), freeing the next hop
	if (rib6_delete(req->vrf_id, GR_IFACE_ID_UNDEF, &req->host, RTE_IPV6_MAX_DEPTH) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

struct list_context {
	uint16_t vrf_id;
	struct gr_nexthop *nh;
};

static void nh_list_cb(struct nexthop *nh, void *priv) {
	struct list_context *ctx = priv;

	if (nh->type != GR_NH_IPV6 || (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX)
	    || rte_ipv6_addr_is_mcast(&nh->ipv6))
		return;

	gr_vec_add(ctx->nh, nh->base);
}

static struct api_out nh6_list(const void *request, void **response) {
	const struct gr_ip6_nh_list_req *req = request;
	struct list_context ctx = {.vrf_id = req->vrf_id, .nh = NULL};
	struct gr_ip6_nh_list_resp *resp = NULL;
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

static void nh6_free(struct nexthop *nh) {
	rib6_delete(nh->vrf_id, nh->iface_id, &nh->ipv6, RTE_IPV6_MAX_DEPTH);
	if (nh->ref_count > 0) {
		nh->flags &= ~(GR_NH_F_REACHABLE | GR_NH_F_PENDING | GR_NH_F_FAILED);
		memset(&nh->mac, 0, sizeof(nh->mac));
	}
}

static void nh6_init(struct event_base *) {
	ip6_output_node = gr_control_input_register_handler("ip6_output", true);
	ndp_na_output_node = gr_control_input_register_handler("ndp_na_output", true);
}

static struct gr_api_handler nh6_add_handler = {
	.name = "ipv6 nexthop add",
	.request_type = GR_IP6_NH_ADD,
	.callback = nh6_add,
};
static struct gr_api_handler nh6_del_handler = {
	.name = "ipv6 nexthop del",
	.request_type = GR_IP6_NH_DEL,
	.callback = nh6_del,
};
static struct gr_api_handler nh6_list_handler = {
	.name = "ipv6 nexthop list",
	.request_type = GR_IP6_NH_LIST,
	.callback = nh6_list,
};

static struct gr_module nh6_module = {
	.name = "ipv6 nexthop",
	.init = nh6_init,
};

static struct nexthop_ops nh_ops = {
	.solicit = nh6_solicit,
	.free = nh6_free,
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&nh6_add_handler);
	gr_register_api_handler(&nh6_del_handler);
	gr_register_api_handler(&nh6_list_handler);
	gr_register_module(&nh6_module);
	nexthop_ops_register(GR_NH_IPV6, &nh_ops);
}
