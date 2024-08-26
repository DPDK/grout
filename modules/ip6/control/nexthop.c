// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_control.h>
#include <gr_iface.h>
#include <gr_ip6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_net_types.h>
#include <gr_queue.h>
#include <gr_stb_ds.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ip6.h>
#include <rte_mempool.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct rte_mempool *nh_pool;

struct nexthop6 *
ip6_nexthop_new(uint16_t vrf_id, uint16_t iface_id, const struct rte_ipv6_addr *ip) {
	struct nexthop6 *nh;
	void *data;
	int ret;

	if ((ret = rte_mempool_get(nh_pool, &data)) < 0)
		return errno_set_null(-ret);

	nh = data;
	nh->vrf_id = vrf_id;
	nh->iface_id = iface_id;
	rte_ipv6_addr_cpy(&nh->ip, ip);

	return nh;
}

struct lookup_filter {
	uint16_t vrf_id;
	const struct rte_ipv6_addr *ip;
	struct nexthop6 *nh;
};

static void nh_lookup_cb(struct rte_mempool *, void *opaque, void *obj, unsigned) {
	struct lookup_filter *filter = opaque;
	struct nexthop6 *nh = obj;
	if (filter->nh == NULL && nh->ref_count > 0 && rte_ipv6_addr_eq(&nh->ip, filter->ip)
	    && nh->vrf_id == filter->vrf_id)
		filter->nh = nh;
}

struct nexthop6 *ip6_nexthop_lookup(uint16_t vrf_id, const struct rte_ipv6_addr *ip) {
	struct lookup_filter filter = {.vrf_id = vrf_id, .ip = ip};
	rte_mempool_obj_iter(nh_pool, nh_lookup_cb, &filter);
	return filter.nh ?: errno_set_null(ENOENT);
}

void ip6_nexthop_decref(struct nexthop6 *nh) {
	if (nh->ref_count <= 1) {
		memset(nh, 0, sizeof(*nh));
		rte_mempool_put(nh_pool, nh);
	} else {
		nh->ref_count--;
	}
}

void ip6_nexthop_incref(struct nexthop6 *nh) {
	nh->ref_count++;
}

static struct api_out nh6_add(const void *request, void **response) {
	const struct gr_ip6_nh_add_req *req = request;
	struct nexthop6 *nh;
	int ret;

	(void)response;

	if (rte_ipv6_addr_is_unspec(&req->nh.host) || rte_ipv6_addr_is_mcast(&req->nh.host))
		return api_out(EINVAL, 0);
	if (req->nh.vrf_id >= IP6_MAX_VRFS)
		return api_out(EOVERFLOW, 0);
	if (iface_from_id(req->nh.iface_id) == NULL)
		return api_out(errno, 0);

	if ((nh = ip6_nexthop_lookup(req->nh.vrf_id, &req->nh.host)) != NULL) {
		if (req->exist_ok && req->nh.iface_id == nh->iface_id
		    && rte_is_same_ether_addr(&req->nh.mac, &nh->lladdr))
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	if ((nh = ip6_nexthop_new(req->nh.vrf_id, req->nh.iface_id, &req->nh.host)) == NULL)
		return api_out(errno, 0);

	rte_ether_addr_copy(&req->nh.mac, &nh->lladdr);
	nh->flags = GR_IP6_NH_F_STATIC | GR_IP6_NH_F_REACHABLE;
	ret = ip6_route_insert(nh->vrf_id, &nh->ip, RTE_IPV6_MAX_DEPTH, nh);

	return api_out(-ret, 0);
}

static struct api_out nh6_del(const void *request, void **response) {
	const struct gr_ip6_nh_del_req *req = request;
	struct nexthop6 *nh;

	(void)response;

	if (req->vrf_id >= IP6_MAX_VRFS)
		return api_out(EOVERFLOW, 0);

	if ((nh = ip6_nexthop_lookup(req->vrf_id, &req->host)) == NULL) {
		if (errno == ENOENT && req->missing_ok)
			return api_out(0, 0);
		return api_out(errno, 0);
	}
	if ((nh->flags & (GR_IP6_NH_F_LOCAL | GR_IP6_NH_F_LINK | GR_IP6_NH_F_GATEWAY))
	    || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	// this also does ip6_nexthop_decref(), freeing the next hop
	if (ip6_route_delete(req->vrf_id, &req->host, RTE_IPV6_MAX_DEPTH) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

struct list_context {
	uint16_t vrf_id;
	struct gr_ip6_nh *nh;
};

static void nh_list_cb(struct rte_mempool *, void *opaque, void *obj, unsigned) {
	struct list_context *ctx = opaque;
	struct nexthop6 *nh = obj;
	struct gr_ip6_nh api_nh;

	if (nh->ref_count == 0 || (nh->vrf_id != ctx->vrf_id && ctx->vrf_id != UINT16_MAX)
	    || rte_ipv6_addr_is_mcast(&nh->ip))
		return;

	api_nh.host = nh->ip;
	api_nh.iface_id = nh->iface_id;
	api_nh.vrf_id = nh->vrf_id;
	rte_ether_addr_copy(&nh->lladdr, &api_nh.mac);
	api_nh.flags = nh->flags;
	arrpush(ctx->nh, api_nh);
}

static struct api_out nh6_list(const void *request, void **response) {
	const struct gr_ip6_nh_list_req *req = request;
	struct list_context ctx = {.vrf_id = req->vrf_id, .nh = NULL};
	struct gr_ip6_nh_list_resp *resp = NULL;
	size_t len;

	rte_mempool_obj_iter(nh_pool, nh_list_cb, &ctx);

	len = sizeof(*resp) + arrlen(ctx.nh) * sizeof(*ctx.nh);
	if ((resp = calloc(len, 1)) == NULL) {
		arrfree(ctx.nh);
		return api_out(ENOMEM, 0);
	}

	resp->n_nhs = arrlen(ctx.nh);
	memcpy(&resp->nhs, ctx.nh, arrlen(ctx.nh) * sizeof(*ctx.nh));
	arrfree(ctx.nh);
	*response = resp;

	return api_out(0, len);
}

static void nh6_init(struct event_base *) {
	nh_pool = rte_mempool_create(
		"ip6_nh", // name
		rte_align32pow2(IP6_MAX_NEXT_HOPS) - 1,
		sizeof(struct nexthop6),
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
		ABORT("rte_mempool_create(ip6_nh) failed");
}

static void nh6_fini(struct event_base *) {
	rte_mempool_free(nh_pool);
	nh_pool = NULL;
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
	.fini = nh6_fini,
	.fini_prio = 20000,
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&nh6_add_handler);
	gr_register_api_handler(&nh6_del_handler);
	gr_register_api_handler(&nh6_list_handler);
	gr_register_module(&nh6_module);
}
