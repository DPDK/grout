// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_control.h>
#include <gr_iface.h>
#include <gr_ip4.h>
#include <gr_ip4_control.h>
#include <gr_log.h>
#include <gr_net_types.h>
#include <gr_queue.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_rcu_qsbr.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct nexthop **addrs;

struct nexthop *ip4_addr_get(uint16_t iface_id) {
	struct nexthop *nh = NULL;
	if (iface_id < MAX_IFACES)
		nh = addrs[iface_id];
	if (nh == NULL)
		errno = ENODEV;
	return nh;
}

static struct api_out addr_add(const void *request, void **response) {
	const struct gr_ip4_addr_add_req *req = request;
	const struct iface *iface;
	struct nexthop *nh;
	uint32_t nh_idx;
	int ret;

	(void)response;

	iface = iface_from_id(req->addr.iface_id);
	if (iface == NULL)
		return api_out(errno, 0);

	if ((nh = ip4_addr_get(req->addr.iface_id)) != NULL) {
		if (req->exist_ok && req->addr.addr.ip == nh->ip
		    && req->addr.addr.prefixlen == nh->prefixlen)
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}
	if (ip4_nexthop_lookup(iface->vrf_id, req->addr.addr.ip, &nh_idx, &nh) == 0)
		return api_out(EADDRINUSE, 0);

	if ((ret = ip4_nexthop_add(iface->vrf_id, req->addr.addr.ip, &nh_idx, &nh)) < 0)
		return api_out(-ret, 0);

	nh->iface_id = req->addr.iface_id;
	nh->prefixlen = req->addr.addr.prefixlen;
	nh->flags = GR_IP4_NH_F_LOCAL | GR_IP4_NH_F_LINK | GR_IP4_NH_F_REACHABLE
		| GR_IP4_NH_F_STATIC;

	if (iface_get_eth_addr(iface->id, &nh->lladdr) < 0)
		if (errno != EOPNOTSUPP)
			return api_out(errno, 0);

	ret = ip4_route_insert(iface->vrf_id, nh->ip, nh->prefixlen, nh_idx, nh);
	if (ret == 0)
		addrs[nh->iface_id] = nh;
	else
		ip4_nexthop_decref(nh);

	return api_out(-ret, 0);
}

static struct api_out addr_del(const void *request, void **response) {
	const struct gr_ip4_addr_del_req *req = request;
	const struct iface *iface;
	struct nexthop *nh;

	(void)response;

	if ((nh = ip4_addr_get(req->addr.iface_id)) == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}
	if (nh->ip != req->addr.addr.ip || nh->prefixlen != req->addr.addr.prefixlen)
		return api_out(ENOENT, 0);

	if ((nh->flags & (GR_IP4_NH_F_LOCAL | GR_IP4_NH_F_LINK)) || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	iface = iface_from_id(req->addr.iface_id);
	if (iface == NULL)
		return api_out(errno, 0);

	ip4_route_delete(iface->vrf_id, nh->ip, nh->prefixlen);
	addrs[req->addr.iface_id] = NULL;

	return api_out(0, 0);
}

static struct api_out addr_list(const void *request, void **response) {
	const struct gr_ip4_addr_list_req *req = request;
	struct gr_ip4_addr_list_resp *resp = NULL;
	struct gr_ip4_ifaddr *addr;
	const struct nexthop *nh;
	uint16_t iface_id, num;
	size_t len;

	num = 0;
	for (iface_id = 0; iface_id < RTE_MAX_ETHPORTS; iface_id++) {
		if (ip4_addr_get(iface_id) != NULL)
			num++;
	}

	len = sizeof(*resp) + num * sizeof(struct gr_ip4_ifaddr);
	if ((resp = calloc(len, 1)) == NULL)
		return api_out(ENOMEM, 0);

	num = 0;
	for (iface_id = 0; iface_id < RTE_MAX_ETHPORTS; iface_id++) {
		nh = ip4_addr_get(iface_id);
		if (nh == NULL || nh->vrf_id != req->vrf_id)
			continue;
		addr = &resp->addrs[resp->n_addrs++];
		addr->addr.ip = nh->ip;
		addr->addr.prefixlen = nh->prefixlen;
		addr->iface_id = nh->iface_id;
	}

	*response = resp;

	return api_out(0, len);
}

static void addr_init(struct event_base *) {
	addrs = rte_calloc(__func__, MAX_IFACES, sizeof(struct nexthop *), RTE_CACHE_LINE_SIZE);
	if (addrs == NULL)
		ABORT("rte_calloc(addrs)");
}

static void addr_fini(struct event_base *) {
	rte_free(addrs);
	addrs = NULL;
}

static struct gr_api_handler addr_add_handler = {
	.name = "ipv4 address add",
	.request_type = GR_IP4_ADDR_ADD,
	.callback = addr_add,
};
static struct gr_api_handler addr_del_handler = {
	.name = "ipv4 address del",
	.request_type = GR_IP4_ADDR_DEL,
	.callback = addr_del,
};
static struct gr_api_handler addr_list_handler = {
	.name = "ipv4 address list",
	.request_type = GR_IP4_ADDR_LIST,
	.callback = addr_list,
};
static struct gr_module addr_module = {
	.name = "ipv4 address",
	.init = addr_init,
	.fini = addr_fini,
};

RTE_INIT(address_constructor) {
	gr_register_api_handler(&addr_add_handler);
	gr_register_api_handler(&addr_del_handler);
	gr_register_api_handler(&addr_list_handler);
	gr_register_module(&addr_module);
}
