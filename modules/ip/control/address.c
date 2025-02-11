// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_ip4.h>
#include <gr_ip4_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_queue.h>
#include <gr_vec.h>

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

static struct hoplist *iface_addrs;

struct hoplist *addr4_get_all(uint16_t iface_id) {
	struct hoplist *addrs;

	if (iface_id >= MAX_IFACES)
		return errno_set_null(ENODEV);

	addrs = &iface_addrs[iface_id];
	if (gr_vec_len(addrs->nh) == 0)
		return errno_set_null(ENOENT);

	return addrs;
}

struct nexthop *addr4_get_preferred(uint16_t iface_id, ip4_addr_t dst) {
	struct hoplist *addrs = addr4_get_all(iface_id);
	struct nexthop *nh;

	if (addrs == NULL)
		return NULL;

	gr_vec_foreach (nh, addrs->nh) {
		if (ip4_addr_same_subnet(dst, nh->ipv4, nh->prefixlen))
			return nh;
	}

	return addrs->nh[0];
}

static struct api_out addr_add(const void *request, void ** /*response*/) {
	const struct gr_ip4_addr_add_req *req = request;
	struct hoplist *ifaddrs;
	const struct iface *iface;
	struct nexthop *nh;
	int ret;

	iface = iface_from_id(req->addr.iface_id);
	if (iface == NULL)
		return api_out(errno, 0);

	ifaddrs = &iface_addrs[iface->id];

	gr_vec_foreach (nh, ifaddrs->nh) {
		if (req->exist_ok && req->addr.addr.ip == nh->ipv4
		    && req->addr.addr.prefixlen == nh->prefixlen)
			return api_out(0, 0);
	}

	if (nh4_lookup(iface->vrf_id, req->addr.addr.ip) != NULL)
		return api_out(EADDRINUSE, 0);

	if ((nh = nh4_new(iface->vrf_id, iface->id, req->addr.addr.ip)) == NULL)
		return api_out(errno, 0);

	nh->prefixlen = req->addr.addr.prefixlen;
	nh->flags = GR_NH_F_LOCAL | GR_NH_F_LINK | GR_NH_F_REACHABLE | GR_NH_F_STATIC;

	if (iface_get_eth_addr(iface->id, &nh->mac) < 0)
		if (errno != EOPNOTSUPP) {
			nexthop_decref(nh);
			return api_out(errno, 0);
		}

	if ((ret = rib4_insert(iface->vrf_id, nh->ipv4, nh->prefixlen, nh)) < 0)
		return api_out(-ret, 0);

	gr_vec_add(ifaddrs->nh, nh);
	gr_event_push(IP_EVENT_ADDR_ADD, nh);

	return api_out(0, 0);
}

static struct api_out addr_del(const void *request, void ** /*response*/) {
	const struct gr_ip4_addr_del_req *req = request;
	struct hoplist *addrs;
	struct nexthop *nh;
	unsigned i = 0;

	if ((addrs = addr4_get_all(req->addr.iface_id)) == NULL)
		return api_out(ENODEV, 0);

	gr_vec_foreach (nh, addrs->nh) {
		if (nh->ipv4 == req->addr.addr.ip && nh->prefixlen == req->addr.addr.prefixlen) {
			break;
		}
		nh = NULL;
		i++;
	}
	if (nh == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}

	if ((nh->flags & (GR_NH_F_LOCAL | GR_NH_F_LINK)) || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	rib4_cleanup(nh);

	gr_vec_del(addrs->nh, i);
	gr_event_push(IP_EVENT_ADDR_DEL, nh);

	return api_out(0, 0);
}

static struct api_out addr_list(const void *request, void **response) {
	const struct gr_ip4_addr_list_req *req = request;
	struct gr_ip4_addr_list_resp *resp = NULL;
	const struct hoplist *addrs;
	struct gr_ip4_ifaddr *addr;
	const struct nexthop *nh;
	uint16_t iface_id, num;
	size_t len;

	num = 0;
	for (iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		addrs = addr4_get_all(iface_id);
		if (addrs == NULL || gr_vec_len(addrs->nh) == 0
		    || addrs->nh[0]->vrf_id != req->vrf_id)
			continue;
		num += gr_vec_len(addrs->nh);
	}

	len = sizeof(*resp) + num * sizeof(struct gr_ip4_ifaddr);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	for (iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		addrs = addr4_get_all(iface_id);
		if (addrs == NULL || gr_vec_len(addrs->nh) == 0
		    || addrs->nh[0]->vrf_id != req->vrf_id)
			continue;
		gr_vec_foreach (nh, addrs->nh) {
			addr = &resp->addrs[resp->n_addrs++];
			addr->addr.ip = nh->ipv4;
			addr->addr.prefixlen = nh->prefixlen;
			addr->iface_id = iface_id;
		}
	}

	*response = resp;

	return api_out(0, len);
}

static void iface_pre_remove_cb(uint32_t /*event*/, const void *obj) {
	const struct iface *iface = obj;
	struct hoplist *ifaddrs;
	struct nexthop *nh;

	ifaddrs = addr4_get_all(iface->id);
	if (ifaddrs == NULL)
		return;

	gr_vec_foreach (nh, ifaddrs->nh)
		rib4_cleanup(nh);

	gr_vec_free(ifaddrs->nh);
}

static void addr_init(struct event_base *) {
	iface_addrs = rte_calloc(__func__, MAX_IFACES, sizeof(struct hoplist), RTE_CACHE_LINE_SIZE);
	if (iface_addrs == NULL)
		ABORT("rte_calloc(addrs)");
}

static void addr_fini(struct event_base *) {
	rte_free(iface_addrs);
	iface_addrs = NULL;
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
	.fini_prio = 2000,
};

static struct gr_event_subscription iface_pre_rm_subscription = {
	.callback = iface_pre_remove_cb,
	.ev_count = 1,
	.ev_types = {IFACE_EVENT_PRE_REMOVE},
};
static struct gr_event_serializer iface_addr_serializer = {
	.size = sizeof(struct gr_nexthop),
	.ev_count = 2,
	.ev_types = {IP_EVENT_ADDR_ADD, IP_EVENT_ADDR_DEL},
};

RTE_INIT(address_constructor) {
	gr_register_api_handler(&addr_add_handler);
	gr_register_api_handler(&addr_del_handler);
	gr_register_api_handler(&addr_list_handler);
	gr_register_module(&addr_module);
	gr_event_subscribe(&iface_pre_rm_subscription);
	gr_event_register_serializer(&iface_addr_serializer);
}
