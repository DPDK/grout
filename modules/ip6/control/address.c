// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_ip6.h>
#include <gr_ip6_control.h>
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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct hoplist *iface_addrs;

static void ip6_push_notification(ip6_event_t id, struct nexthop *nh) {
	struct gr_nexthop api_nh = {
		.family = nh->family,
		.ipv6 = nh->ipv6,
		.iface_id = nh->iface_id,
		.vrf_id = nh->vrf_id,
		.mac = nh->lladdr,
		.flags = nh->flags,
	};

	gr_event_push(id, sizeof(api_nh), &api_nh);
}

struct hoplist *addr6_get_all(uint16_t iface_id) {
	struct hoplist *addrs;

	if (iface_id >= MAX_IFACES)
		return errno_set_null(ENODEV);

	addrs = &iface_addrs[iface_id];
	if (gr_vec_len(addrs->nh) == 0)
		return errno_set_null(ENOENT);

	return addrs;
}

struct nexthop *addr6_get_preferred(uint16_t iface_id, const struct rte_ipv6_addr *dst) {
	struct hoplist *addrs = addr6_get_all(iface_id);
	struct nexthop *pref = NULL, *nh;

	if (addrs == NULL)
		return NULL;

	gr_vec_foreach (nh, addrs->nh) {
		if (rte_ipv6_addr_eq_prefix(dst, &nh->ipv6, nh->prefixlen))
			return nh;
		if (pref == NULL && !rte_ipv6_addr_is_linklocal(&nh->ipv6))
			pref = nh;
	}

	return pref;
}

static struct hoplist *iface_mcast_addrs;

struct nexthop *mcast6_get_member(uint16_t iface_id, const struct rte_ipv6_addr *mcast) {
	struct hoplist *maddrs;
	struct nexthop *nh;

	if (iface_id >= MAX_IFACES)
		return NULL;

	maddrs = &iface_mcast_addrs[iface_id];
	gr_vec_foreach (nh, maddrs->nh) {
		if (rte_ipv6_addr_eq(&nh->ipv6, mcast))
			return nh;
	}

	return NULL;
}

static int mcast6_addr_add(struct iface *iface, const struct rte_ipv6_addr *ip) {
	struct hoplist *maddrs = &iface_mcast_addrs[iface->id];
	struct nexthop *nh;

	LOG(INFO, "%s: joining multicast group " IP6_F, iface->name, ip);

	gr_vec_foreach (nh, maddrs->nh) {
		if (rte_ipv6_addr_eq(&nh->ipv6, ip))
			return errno_set(EEXIST);
	}

	if ((nh = nh6_lookup(iface->vrf_id, iface->id, ip)) == NULL) {
		if ((nh = nh6_new(iface->vrf_id, iface->id, ip)) == NULL)
			return errno_set(-errno);
		rte_ether_mcast_from_ipv6(&nh->lladdr, ip);
	}

	nexthop_incref(nh);
	nh->flags = GR_NH_F_REACHABLE | GR_NH_F_STATIC | GR_NH_F_MCAST;
	gr_vec_add(maddrs->nh, nh);

	// add ethernet filter
	return iface_add_eth_addr(iface->id, &nh->lladdr);
}

static int mcast6_addr_del(struct iface *iface, const struct rte_ipv6_addr *ip) {
	struct hoplist *maddrs = &iface_mcast_addrs[iface->id];
	struct nexthop *nh = NULL;
	unsigned i = 0;
	int ret;

	LOG(INFO, "%s: leaving multicast group " IP6_F, iface->name, ip);

	gr_vec_foreach (nh, maddrs->nh) {
		if (rte_ipv6_addr_eq(&nh->ipv6, ip))
			break;
		nh = NULL;
		i++;
	}
	if (nh == NULL)
		return errno_set(ENOENT);

	// shift remaining addresses
	gr_vec_del(maddrs->nh, i);

	// remove ethernet filter
	ret = iface_del_eth_addr(iface->id, &nh->lladdr);
	nexthop_decref(nh);

	return ret;
}

static int
iface6_addr_add(const struct iface *iface, const struct rte_ipv6_addr *ip, uint8_t prefixlen) {
	struct hoplist *addrs;
	struct nexthop *nh;
	int ret;

	if (iface == NULL || ip == NULL || prefixlen > RTE_IPV6_MAX_DEPTH)
		return errno_set(EINVAL);

	addrs = &iface_addrs[iface->id];

	gr_vec_foreach (nh, addrs->nh) {
		if (prefixlen == nh->prefixlen && rte_ipv6_addr_eq(&nh->ipv6, ip))
			return errno_set(EEXIST);
	}

	if (nh6_lookup(iface->vrf_id, iface->id, ip) != NULL)
		return errno_set(EADDRINUSE);

	if ((nh = nh6_new(iface->vrf_id, iface->id, ip)) == NULL)
		return errno_set(-errno);

	nh->prefixlen = prefixlen;
	nh->flags = GR_NH_F_LOCAL | GR_NH_F_LINK | GR_NH_F_REACHABLE | GR_NH_F_STATIC;

	if ((ret = iface_get_eth_addr(iface->id, &nh->lladdr)) < 0)
		if (errno != EOPNOTSUPP) {
			nexthop_decref(nh);
			return errno_set(-ret);
		}

	if ((ret = rib6_insert(iface->vrf_id, iface->id, ip, nh->prefixlen, nh)) < 0)
		return errno_set(-ret);

	gr_vec_add(addrs->nh, nh);
	ip6_push_notification(IP6_EVENT_ADDR_ADD, nh);

	return 0;
}

static struct api_out addr6_add(const void *request, void ** /*response*/) {
	const struct gr_ip6_addr_add_req *req = request;
	struct rte_ipv6_addr solicited_node;
	struct iface *iface;
	int ret;

	iface = iface_from_id(req->addr.iface_id);
	if (iface == NULL)
		return api_out(errno, 0);

	if ((ret = iface6_addr_add(iface, &req->addr.addr.ip, req->addr.addr.prefixlen)) < 0)
		if (ret != -EEXIST || !req->exist_ok)
			return api_out(-ret, 0);

	// join the solicited node multicast group
	rte_ipv6_solnode_from_addr(&solicited_node, &req->addr.addr.ip);
	if (mcast6_addr_add(iface, &solicited_node) < 0) {
		if (errno != EOPNOTSUPP)
			return api_out(errno, 0);
	}

	return api_out(0, 0);
}

static struct api_out addr6_del(const void *request, void ** /*response*/) {
	const struct gr_ip6_addr_del_req *req = request;
	struct rte_ipv6_addr solicited_node;
	struct nexthop *nh = NULL;
	struct hoplist *addrs;
	unsigned i = 0;

	if ((addrs = addr6_get_all(req->addr.iface_id)) == NULL)
		return api_out(errno, 0);

	gr_vec_foreach (nh, addrs->nh) {
		if (rte_ipv6_addr_eq(&nh->ipv6, &req->addr.addr.ip)
		    && nh->prefixlen == req->addr.addr.prefixlen) {
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

	rib6_cleanup(nh);

	// shift the remaining addresses
	gr_vec_del(addrs->nh, i);

	// leave the solicited node multicast group
	rte_ipv6_solnode_from_addr(&solicited_node, &req->addr.addr.ip);
	if (mcast6_addr_del(iface_from_id(req->addr.iface_id), &solicited_node) < 0)
		return api_out(errno, 0);

	ip6_push_notification(IP6_EVENT_ADDR_DEL, nh);
	return api_out(0, 0);
}

static struct api_out addr6_list(const void *request, void **response) {
	const struct gr_ip6_addr_list_req *req = request;
	struct gr_ip6_addr_list_resp *resp = NULL;
	const struct hoplist *addrs;
	struct gr_ip6_ifaddr *addr;
	const struct nexthop *nh;
	uint16_t iface_id, num;
	size_t len;

	num = 0;
	for (iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		addrs = addr6_get_all(iface_id);
		if (addrs == NULL || gr_vec_len(addrs->nh) == 0
		    || addrs->nh[0]->vrf_id != req->vrf_id)
			continue;
		num += gr_vec_len(addrs->nh);
	}

	len = sizeof(*resp) + num * sizeof(struct gr_ip6_ifaddr);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	for (iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		addrs = addr6_get_all(iface_id);
		if (addrs == NULL)
			continue;
		gr_vec_foreach (nh, addrs->nh) {
			if (nh->vrf_id != req->vrf_id)
				continue;
			addr = &resp->addrs[resp->n_addrs++];
			addr->addr.ip = nh->ipv6;
			addr->addr.prefixlen = nh->prefixlen;
			addr->iface_id = nh->iface_id;
		}
	}

	*response = resp;

	return api_out(0, len);
}

static const struct rte_ipv6_addr well_known_mcast_addrs[] = {
	RTE_IPV6_ADDR_ALLNODES_IFACE_LOCAL,
	RTE_IPV6_ADDR_ALLNODES_LINK_LOCAL,
	RTE_IPV6_ADDR_ALLROUTERS_IFACE_LOCAL,
	RTE_IPV6_ADDR_ALLROUTERS_LINK_LOCAL,
	RTE_IPV6_ADDR_ALLROUTERS_SITE_LOCAL,
};

static void ip6_iface_event_handler(iface_event_t event, struct iface *iface) {
	struct rte_ipv6_addr link_local, solicited_node;
	struct rte_ether_addr mac;
	struct nexthop *nh;
	unsigned i;

	switch (event) {
	case IFACE_EVENT_POST_ADD:
		if (iface_get_eth_addr(iface->id, &mac) == 0) {
			rte_ipv6_llocal_from_ethernet(&link_local, &mac);
			if (iface6_addr_add(iface, &link_local, 64) < 0)
				errno_log(errno, "iface_addr_add");

			rte_ipv6_solnode_from_addr(&solicited_node, &link_local);
			if (mcast6_addr_add(iface, &solicited_node) < 0)
				LOG(INFO, "%s: mcast_addr_add: %s", iface->name, strerror(errno));
		}
		for (i = 0; i < ARRAY_DIM(well_known_mcast_addrs); i++) {
			if (mcast6_addr_add(iface, &well_known_mcast_addrs[i]) < 0)
				LOG(INFO, "%s: mcast_addr_add: %s", iface->name, strerror(errno));
		}
		break;
	case IFACE_EVENT_PRE_REMOVE:
		struct hoplist *addrs = &iface_addrs[iface->id];

		gr_vec_foreach (nh, addrs->nh)
			rib6_cleanup(nh);
		gr_vec_free(addrs->nh);

		addrs = &iface_mcast_addrs[iface->id];
		gr_vec_foreach (nh, addrs->nh) {
			// remove ethernet filter
			if (iface_del_eth_addr(iface->id, &nh->lladdr) < 0)
				LOG(INFO, "%s: mcast_addr_del: %s", iface->name, strerror(errno));
			nexthop_decref(nh);
		}
		gr_vec_free(addrs->nh);
		break;
	default:
		break;
	}
}

static void addr6_init(struct event_base *) {
	iface_addrs = rte_calloc(__func__, MAX_IFACES, sizeof(*iface_addrs), RTE_CACHE_LINE_SIZE);
	if (iface_addrs == NULL)
		ABORT("rte_calloc(iface_addrs)");
	iface_mcast_addrs = rte_calloc(
		__func__, MAX_IFACES, sizeof(*iface_mcast_addrs), RTE_CACHE_LINE_SIZE
	);
	if (iface_mcast_addrs == NULL)
		ABORT("rte_calloc(iface_mcast_addrs)");
}

static void addr6_fini(struct event_base *) {
	rte_free(iface_addrs);
	iface_addrs = NULL;
	rte_free(iface_mcast_addrs);
	iface_mcast_addrs = NULL;
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
