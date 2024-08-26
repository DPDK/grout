// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_control.h>
#include <gr_iface.h>
#include <gr_ip6.h>
#include <gr_ip6_control.h>
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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct hoplist6 *iface_addrs;

static struct hoplist6 *ip6_addr_get_all(uint16_t iface_id) {
	struct hoplist6 *addrs;

	if (iface_id >= MAX_IFACES)
		return errno_set_null(ENODEV);

	addrs = &iface_addrs[iface_id];
	if (addrs->count == 0)
		return errno_set_null(ENOENT);

	return addrs;
}

static int
iface6_addr_add(const struct iface *iface, const struct rte_ipv6_addr *ip, uint8_t prefixlen) {
	struct hoplist6 *addrs;
	unsigned addr_index;
	struct nexthop6 *nh;
	int ret;

	if (iface == NULL || ip == NULL || prefixlen > RTE_IPV6_MAX_DEPTH)
		return errno_set(EINVAL);

	addrs = &iface_addrs[iface->id];

	for (addr_index = 0; addr_index < addrs->count; addr_index++) {
		nh = addrs->nh[addr_index];
		if (prefixlen == nh->prefixlen && rte_ipv6_addr_eq(&nh->ip, ip))
			return errno_set(EEXIST);
	}

	if (addrs->count == IP6_HOPLIST_MAX_SIZE)
		return errno_set(ENOSPC);

	if (ip6_nexthop_lookup(iface->vrf_id, ip) != NULL)
		return errno_set(EADDRINUSE);

	if ((nh = ip6_nexthop_new(iface->vrf_id, iface->id, ip)) == NULL)
		return errno_set(-errno);

	nh->prefixlen = prefixlen;
	nh->flags = GR_IP6_NH_F_LOCAL | GR_IP6_NH_F_LINK | GR_IP6_NH_F_REACHABLE
		| GR_IP6_NH_F_STATIC;

	if ((ret = iface_get_eth_addr(iface->id, &nh->lladdr)) < 0)
		if (ret != EOPNOTSUPP) {
			ip6_nexthop_decref(nh);
			return errno_set(-ret);
		}

	if ((ret = ip6_route_insert(iface->vrf_id, &nh->ip, nh->prefixlen, nh)) < 0)
		return errno_set(-ret);

	addrs->nh[addr_index] = nh;
	addrs->count++;

	return 0;
}

static struct api_out addr6_add(const void *request, void **response) {
	const struct gr_ip6_addr_add_req *req = request;
	struct iface *iface;
	int ret;

	(void)response;

	iface = iface_from_id(req->addr.iface_id);
	if (iface == NULL)
		return api_out(errno, 0);

	if ((ret = iface6_addr_add(iface, &req->addr.addr.ip, req->addr.addr.prefixlen)) < 0)
		if (ret != -EEXIST || !req->exist_ok)
			return api_out(-ret, 0);

	return api_out(0, 0);
}

static struct api_out addr6_del(const void *request, void **response) {
	const struct gr_ip6_addr_del_req *req = request;
	struct nexthop6 *nh = NULL;
	struct hoplist6 *addrs;
	unsigned i;

	(void)response;

	if ((addrs = ip6_addr_get_all(req->addr.iface_id)) == NULL)
		return api_out(errno, 0);

	for (i = 0; i < addrs->count; i++) {
		if (rte_ipv6_addr_eq(&addrs->nh[i]->ip, &req->addr.addr.ip)
		    && addrs->nh[i]->prefixlen == req->addr.addr.prefixlen) {
			nh = addrs->nh[i];
			break;
		}
	}
	if (nh == NULL) {
		if (req->missing_ok)
			return api_out(0, 0);
		return api_out(ENOENT, 0);
	}

	if ((nh->flags & (GR_IP6_NH_F_LOCAL | GR_IP6_NH_F_LINK)) || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	ip6_route_cleanup(nh);

	// shift the remaining addresses
	for (; i < addrs->count - 1; i++)
		addrs->nh[i] = addrs->nh[i + 1];
	addrs->count--;

	return api_out(0, 0);
}

static struct api_out addr6_list(const void *request, void **response) {
	const struct gr_ip6_addr_list_req *req = request;
	struct gr_ip6_addr_list_resp *resp = NULL;
	const struct hoplist6 *addrs;
	struct gr_ip6_ifaddr *addr;
	uint16_t iface_id, num;
	size_t len;

	num = 0;
	for (iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		addrs = ip6_addr_get_all(iface_id);
		if (addrs == NULL || addrs->count == 0 || addrs->nh[0]->vrf_id != req->vrf_id)
			continue;
		num += addrs->count;
	}

	len = sizeof(*resp) + num * sizeof(struct gr_ip6_ifaddr);
	if ((resp = calloc(len, 1)) == NULL)
		return api_out(ENOMEM, 0);

	for (iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		addrs = ip6_addr_get_all(iface_id);
		if (addrs == NULL || addrs->count == 0 || addrs->nh[0]->vrf_id != req->vrf_id)
			continue;
		for (unsigned i = 0; i < addrs->count; i++) {
			const struct nexthop6 *nh = addrs->nh[i];
			addr = &resp->addrs[resp->n_addrs++];
			rte_ipv6_addr_cpy(&addr->addr.ip, &nh->ip);
			addr->addr.prefixlen = nh->prefixlen;
			addr->iface_id = nh->iface_id;
		}
	}

	*response = resp;

	return api_out(0, len);
}

static void ip6_iface_event_handler(iface_event_t event, struct iface *iface) {
	unsigned i;

	switch (event) {
	case IFACE_EVENT_PRE_REMOVE:
		struct hoplist6 *addrs = &iface_addrs[iface->id];
		for (i = 0; i < addrs->count; i++)
			ip6_route_cleanup(addrs->nh[i]);

		memset(addrs, 0, sizeof(*addrs));
		break;
	default:
		break;
	}
}

static void addr6_init(struct event_base *) {
	iface_addrs = rte_calloc(
		__func__, MAX_IFACES, sizeof(struct hoplist6), RTE_CACHE_LINE_SIZE
	);
	if (iface_addrs == NULL)
		ABORT("rte_calloc(iface_addrs)");
}

static void addr6_fini(struct event_base *) {
	rte_free(iface_addrs);
	iface_addrs = NULL;
}

static struct gr_api_handler addr6_add_handler = {
	.name = "ipv6 address add",
	.request_type = GR_IP6_ADDR_ADD,
	.callback = addr6_add,
};
static struct gr_api_handler addr6_del_handler = {
	.name = "ipv6 address del",
	.request_type = GR_IP6_ADDR_DEL,
	.callback = addr6_del,
};
static struct gr_api_handler addr6_list_handler = {
	.name = "ipv6 address list",
	.request_type = GR_IP6_ADDR_LIST,
	.callback = addr6_list,
};
static struct gr_module addr6_module = {
	.name = "ipv6 address",
	.init = addr6_init,
	.fini = addr6_fini,
	.fini_prio = 2000,
};

static struct iface_event_handler iface_event_address_handler = {
	.callback = ip6_iface_event_handler,
};

RTE_INIT(address_constructor) {
	gr_register_api_handler(&addr6_add_handler);
	gr_register_api_handler(&addr6_del_handler);
	gr_register_api_handler(&addr6_list_handler);
	gr_register_module(&addr6_module);
	iface_event_register_handler(&iface_event_address_handler);
}
