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

static struct nh_pool *nh_pool;

struct nexthop *ip4_nexthop_new(uint16_t vrf_id, uint16_t iface_id, ip4_addr_t ip) {
	return nexthop_new(nh_pool, vrf_id, iface_id, &ip);
}

struct nexthop *ip4_nexthop_lookup(uint16_t vrf_id, ip4_addr_t ip) {
	return nexthop_lookup(nh_pool, vrf_id, &ip);
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

	if ((nh = ip4_nexthop_lookup(req->nh.vrf_id, req->nh.ipv4)) != NULL) {
		if (req->exist_ok && req->nh.iface_id == nh->iface_id
		    && rte_is_same_ether_addr(&req->nh.mac, &nh->lladdr))
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	if ((nh = ip4_nexthop_new(req->nh.vrf_id, req->nh.iface_id, req->nh.ipv4)) == NULL)
		return api_out(errno, 0);

	nh->lladdr = req->nh.mac;
	nh->flags = GR_NH_F_STATIC | GR_NH_F_REACHABLE;
	ret = ip4_route_insert(nh->vrf_id, nh->ipv4, 32, nh);

	return api_out(-ret, 0);
}

static struct api_out nh4_del(const void *request, void ** /*response*/) {
	const struct gr_ip4_nh_del_req *req = request;
	struct nexthop *nh;

	if (req->vrf_id >= MAX_VRFS)
		return api_out(EOVERFLOW, 0);

	if ((nh = ip4_nexthop_lookup(req->vrf_id, req->host)) == NULL) {
		if (errno == ENOENT && req->missing_ok)
			return api_out(0, 0);
		return api_out(errno, 0);
	}
	if ((nh->flags & (GR_NH_F_LOCAL | GR_NH_F_LINK | GR_NH_F_GATEWAY)) || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	// this also does ip4_nexthop_decref(), freeing the next hop
	if (ip4_route_delete(req->vrf_id, req->host, 32) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

struct list_context {
	uint16_t vrf_id;
	struct gr_nexthop *nh;
};

static void nh_list_cb(struct nexthop *nh, void *priv) {
	struct list_context *ctx = priv;
	struct gr_nexthop api_nh;

	if (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX)
		return;

	api_nh.ipv4 = nh->ipv4;
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

	nh_pool_iter(nh_pool, nh_list_cb, &ctx);

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

static void nh4_init(struct event_base *ev_base) {
	struct nh_pool_opts opts = {
		.solicit_nh = arp_output_request_solicit,
		.free_nh = ip4_route_cleanup,
		.num_nexthops = IP4_MAX_NEXT_HOPS,
	};
	nh_pool = nh_pool_new(AF_INET, ev_base, &opts);
	if (nh_pool == NULL)
		ABORT("nh_pool_new(AF_INET) failed");
}

static void nh4_fini(struct event_base *) {
	nh_pool_free(nh_pool);
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
