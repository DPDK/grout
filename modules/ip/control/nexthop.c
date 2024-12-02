// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
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
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_mempool.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_mempool *nh_pool;

struct nexthop *ip4_nexthop_new(uint16_t vrf_id, uint16_t iface_id, ip4_addr_t ip) {
	struct nexthop *nh;
	void *data;
	int ret;

	if ((ret = rte_mempool_get(nh_pool, &data)) < 0)
		return errno_set_null(-ret);

	nh = data;
	nh->vrf_id = vrf_id;
	nh->iface_id = iface_id;
	nh->ip = ip;

	return nh;
}

struct lookup_filter {
	uint16_t vrf_id;
	ip4_addr_t ip;
	struct nexthop *nh;
};

static void nh_lookup_cb(struct rte_mempool *, void *opaque, void *obj, unsigned /*obj_idx*/) {
	struct lookup_filter *filter = opaque;
	struct nexthop *nh = obj;
	if (filter->nh == NULL && nh->ref_count > 0 && nh->ip == filter->ip
	    && nh->vrf_id == filter->vrf_id)
		filter->nh = nh;
}

struct nexthop *ip4_nexthop_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	struct lookup_filter filter = {.vrf_id = vrf_id, .ip = ip};
	rte_mempool_obj_iter(nh_pool, nh_lookup_cb, &filter);
	return filter.nh ?: errno_set_null(ENOENT);
}

void ip4_nexthop_decref(struct nexthop *nh) {
	if (nh->ref_count <= 1) {
		rte_spinlock_lock(&nh->lock);
		// Flush all held packets.
		struct rte_mbuf *m = nh->held_pkts_head;
		while (m != NULL) {
			struct rte_mbuf *next = queue_mbuf_data(m)->next;
			rte_pktmbuf_free(m);
			m = next;
		}
		rte_spinlock_unlock(&nh->lock);
		memset(nh, 0, sizeof(*nh));
		rte_mempool_put(nh_pool, nh);
	} else {
		nh->ref_count--;
	}
}

void ip4_nexthop_incref(struct nexthop *nh) {
	nh->ref_count++;
}

static struct api_out nh4_add(const void *request, void ** /*response*/) {
	const struct gr_ip4_nh_add_req *req = request;
	struct nexthop *nh;
	int ret;

	if (req->nh.host == 0)
		return api_out(EINVAL, 0);
	if (req->nh.vrf_id >= IP4_MAX_VRFS)
		return api_out(EOVERFLOW, 0);
	if (iface_from_id(req->nh.iface_id) == NULL)
		return api_out(errno, 0);

	if ((nh = ip4_nexthop_lookup(req->nh.vrf_id, req->nh.host)) != NULL) {
		if (req->exist_ok && req->nh.iface_id == nh->iface_id
		    && rte_is_same_ether_addr(&req->nh.mac, &nh->lladdr))
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	if ((nh = ip4_nexthop_new(req->nh.vrf_id, req->nh.iface_id, req->nh.host)) == NULL)
		return api_out(errno, 0);

	nh->lladdr = req->nh.mac;
	nh->flags = GR_IP4_NH_F_STATIC | GR_IP4_NH_F_REACHABLE;
	ret = ip4_route_insert(nh->vrf_id, nh->ip, 32, nh);

	return api_out(-ret, 0);
}

static struct api_out nh4_del(const void *request, void ** /*response*/) {
	const struct gr_ip4_nh_del_req *req = request;
	struct nexthop *nh;

	if (req->vrf_id >= IP4_MAX_VRFS)
		return api_out(EOVERFLOW, 0);

	if ((nh = ip4_nexthop_lookup(req->vrf_id, req->host)) == NULL) {
		if (errno == ENOENT && req->missing_ok)
			return api_out(0, 0);
		return api_out(errno, 0);
	}
	if ((nh->flags & (GR_IP4_NH_F_LOCAL | GR_IP4_NH_F_LINK | GR_IP4_NH_F_GATEWAY))
	    || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	// this also does ip4_nexthop_decref(), freeing the next hop
	if (ip4_route_delete(req->vrf_id, req->host, 32) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

struct list_context {
	uint16_t vrf_id;
	struct gr_ip4_nh *nh;
};

static void nh_list_cb(struct rte_mempool *, void *opaque, void *obj, unsigned /*obj_idx*/) {
	struct list_context *ctx = opaque;
	struct nexthop *nh = obj;
	struct gr_ip4_nh api_nh;

	if (nh->ref_count == 0 || (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX))
		return;

	api_nh.host = nh->ip;
	api_nh.iface_id = nh->iface_id;
	api_nh.vrf_id = nh->vrf_id;
	api_nh.mac = nh->lladdr;
	api_nh.flags = nh->flags;
	if (nh->last_reply > 0)
		api_nh.age = (rte_get_tsc_cycles() - nh->last_reply) / rte_get_tsc_hz();
	else
		api_nh.age = 0;
	api_nh.held_pkts = nh->held_pkts_num;
	gr_vec_add(ctx->nh, api_nh);
}

static struct api_out nh4_list(const void *request, void **response) {
	const struct gr_ip4_nh_list_req *req = request;
	struct list_context ctx = {.vrf_id = req->vrf_id, .nh = NULL};
	struct gr_ip4_nh_list_resp *resp = NULL;
	size_t len;

	rte_mempool_obj_iter(nh_pool, nh_list_cb, &ctx);

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

static void nh_gc_cb(struct rte_mempool *, void * /*opaque*/, void *obj, unsigned /*obj_idx*/) {
	uint64_t now = rte_get_tsc_cycles();
	uint64_t reply_age, request_age;
	unsigned probes, max_probes;
	struct nexthop *nh = obj;

	max_probes = IP4_NH_UCAST_PROBES + IP4_NH_BCAST_PROBES;

	if (nh->ref_count == 0 || nh->flags & GR_IP4_NH_F_STATIC)
		return;

	reply_age = (now - nh->last_reply) / rte_get_tsc_hz();
	request_age = (now - nh->last_request) / rte_get_tsc_hz();
	probes = nh->ucast_probes + nh->bcast_probes;

	if (nh->flags & (GR_IP4_NH_F_PENDING | GR_IP4_NH_F_STALE) && request_age > probes) {
		if (probes >= max_probes && !(nh->flags & GR_IP4_NH_F_GATEWAY)) {
			LOG(DEBUG,
			    IP4_F " vrf=%u failed_probes=%u held_pkts=%u: %s -> failed",
			    &nh->ip,
			    nh->vrf_id,
			    probes,
			    nh->held_pkts_num,
			    gr_ip4_nh_f_name(nh->flags & (GR_IP4_NH_F_PENDING | GR_IP4_NH_F_STALE))
			);
			nh->flags &= ~(GR_IP4_NH_F_PENDING | GR_IP4_NH_F_STALE);
			nh->flags |= GR_IP4_NH_F_FAILED;
		} else {
			if (arp_output_request_solicit(nh) < 0)
				LOG(ERR, "arp_output_request_solicit: %s", strerror(errno));
		}
	} else if (nh->flags & GR_IP4_NH_F_REACHABLE && reply_age > IP4_NH_LIFETIME_REACHABLE) {
		nh->flags &= ~GR_IP4_NH_F_REACHABLE;
		nh->flags |= GR_IP4_NH_F_STALE;
	} else if (nh->flags & GR_IP4_NH_F_FAILED && request_age > IP4_NH_LIFETIME_UNREACHABLE) {
		LOG(DEBUG,
		    IP4_F " vrf=%u failed_probes=%u held_pkts=%u: failed -> <destroy>",
		    &nh->ip,
		    nh->vrf_id,
		    probes,
		    nh->held_pkts_num);

		// this also does ip4_nexthop_decref(), freeing the next hop
		// and buffered packets.
		ip4_route_cleanup(nh);
	}
}

static void nexthop_gc(evutil_socket_t, short /*what*/, void * /*priv*/) {
	rte_mempool_obj_iter(nh_pool, nh_gc_cb, NULL);
}

static struct event *nh_gc_timer;

static void nh4_init(struct event_base *ev_base) {
	nh_pool = rte_mempool_create(
		"ip4_nh", // name
		rte_align32pow2(IP4_MAX_NEXT_HOPS) - 1,
		sizeof(struct nexthop),
		0, // cache size
		0, // priv size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		SOCKET_ID_ANY,
		0 // flags
	);
	if (nh_pool == NULL)
		ABORT("rte_mempool_create(ip4_nh) failed");

	nh_gc_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, nexthop_gc, NULL);
	if (nh_gc_timer == NULL)
		ABORT("event_new() failed");
	struct timeval tv = {.tv_sec = 1};
	if (event_add(nh_gc_timer, &tv) < 0)
		ABORT("event_add() failed");
}

static void nh4_fini(struct event_base *) {
	event_free(nh_gc_timer);
	nh_gc_timer = NULL;
	rte_mempool_free(nh_pool);
	nh_pool = NULL;
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
	.init = nh4_init,
	.fini = nh4_fini,
	.fini_prio = 20000,
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&nh4_add_handler);
	gr_register_api_handler(&nh4_del_handler);
	gr_register_api_handler(&nh4_list_handler);
	gr_register_module(&nh4_module);
}
