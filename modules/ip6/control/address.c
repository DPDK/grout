// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "arr.h"
#include "event.h"
#include "iface.h"
#include "ip6.h"
#include "ip6_datapath.h"
#include "log.h"
#include "module.h"
#include "netlink.h"
#include "rcu.h"

#include <gr_ip6.h>
#include <gr_net_types.h>

#include <event2/event.h>
#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

LOG_TYPE("address");

static struct hoplist *iface_addrs;

struct hoplist *addr6_get_all(uint16_t iface_id) {
	struct hoplist *addrs;

	if (iface_id >= GR_MAX_IFACES)
		return errno_set_null(ENODEV);

	addrs = &iface_addrs[iface_id];
	if (arr_len(addrs->nh) == 0)
		return errno_set_null(ENOENT);

	return addrs;
}

struct nexthop *addr6_get_preferred(uint16_t iface_id, const struct rte_ipv6_addr *dst) {
	struct hoplist *addrs = addr6_get_all(iface_id);
	const struct nexthop_info_l3 *l3;
	struct nexthop *pref = NULL, *nh;

	if (addrs == NULL)
		return NULL;

	arr_foreach (nh, addrs->nh) {
		l3 = nexthop_info_l3(nh);
		if (rte_ipv6_addr_eq_prefix(dst, &l3->ipv6, l3->prefixlen))
			return nh;
		if (pref == NULL && !rte_ipv6_addr_is_linklocal(&l3->ipv6))
			pref = nh;
	}

	return pref;
}

struct nexthop *addr6_get_linklocal(uint16_t iface_id) {
	struct hoplist *addrs = addr6_get_all(iface_id);
	const struct nexthop_info_l3 *l3;
	struct nexthop *nh;

	if (addrs == NULL)
		return NULL;

	arr_foreach (nh, addrs->nh) {
		l3 = nexthop_info_l3(nh);
		if (rte_ipv6_addr_is_linklocal(&l3->ipv6))
			return nh;
	}

	return errno_set_null(EADDRNOTAVAIL);
}

static struct hoplist *iface_mcast_addrs;

struct nexthop *mcast6_get_member(uint16_t iface_id, const struct rte_ipv6_addr *mcast) {
	const struct nexthop_info_l3 *l3;
	struct hoplist *maddrs;
	struct nexthop *nh;

	if (iface_id >= GR_MAX_IFACES)
		return NULL;

	maddrs = &iface_mcast_addrs[iface_id];
	arr_foreach (nh, maddrs->nh) {
		l3 = nexthop_info_l3(nh);
		if (rte_ipv6_addr_eq(&l3->ipv6, mcast))
			return nh;
	}

	return NULL;
}

static int mcast6_addr_add(const struct iface *iface, const struct rte_ipv6_addr *ip) {
	struct hoplist *maddrs = &iface_mcast_addrs[iface->id];
	struct nexthop *nh;

	LOG(INFO, "%s: joining multicast group " IP6_F, iface->name, ip);

	arr_foreach (nh, maddrs->nh) {
		const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
		if (rte_ipv6_addr_eq(&l3->ipv6, ip)) {
			nexthop_incref(nh);
			return errno_set(EEXIST);
		}
	}

	if ((nh = nh6_lookup(iface->vrf_id, GR_IFACE_ID_UNDEF, ip)) == NULL) {
		struct gr_nexthop_base base = {
			.type = GR_NH_T_L3,
			.iface_id = GR_IFACE_ID_UNDEF,
			.vrf_id = iface->vrf_id,
			.origin = GR_NH_ORIGIN_INTERNAL,
		};
		struct gr_nexthop_info_l3 l3 = {
			.af = GR_AF_IP6,
			.ipv6 = *ip,
			.state = GR_NH_S_REACHABLE,
			.flags = GR_NH_F_STATIC | GR_NH_F_MCAST,
		};

		if ((nh = nexthop_new(&base, &l3)) == NULL)
			return errno_set(errno);
	} else {
		nexthop_incref(nh);
	}

	// arr_add may realloc() and free the old vector
	// Duplicate the whole vector and append to the clone.
	arr struct nexthop **nhs_copy = NULL;
	arr struct nexthop **nhs_old = maddrs->nh;
	arr_cap_set(nhs_copy, arr_len(nhs_old) + 1); // avoid malloc+realloc
	arr_extend(nhs_copy, nhs_old);
	arr_add(nhs_copy, nh);
	maddrs->nh = nhs_copy;
	if (nhs_old != NULL) {
		// Once all datapath workers have seen the new clone, free the old one.
		rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
		arr_free(nhs_old);
	}

	return 0;
}

static int mcast6_addr_del(const struct iface *iface, const struct rte_ipv6_addr *ip) {
	struct hoplist *maddrs = &iface_mcast_addrs[iface->id];
	const struct nexthop_info_l3 *l3;
	struct nexthop *nh = NULL;
	unsigned i = 0;
	int ret = 0;

	arr_foreach (nh, maddrs->nh) {
		l3 = nexthop_info_l3(nh);
		if (rte_ipv6_addr_eq(&l3->ipv6, ip))
			break;
		nh = NULL;
		i++;
	}
	if (nh == NULL)
		return errno_set(ENOENT);

	// shift remaining addresses
	arr_del(maddrs->nh, i);
	if (arr_len(maddrs->nh) == 0)
		arr_free(maddrs->nh);

	nexthop_decref(nh);

	return ret;
}

static int
iface6_addr_add(const struct iface *iface, const struct rte_ipv6_addr *ip, uint8_t prefixlen) {
	struct rte_ipv6_addr solicited_node;
	struct hoplist *addrs;
	struct nexthop *nh;
	int ret;

	if (iface == NULL || ip == NULL || prefixlen > RTE_IPV6_MAX_DEPTH)
		return errno_set(EINVAL);

	if (iface->mode != GR_IFACE_MODE_VRF)
		return errno_set(EMEDIUMTYPE);

	addrs = &iface_addrs[iface->id];

	arr_foreach (nh, addrs->nh) {
		const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
		if (prefixlen == l3->prefixlen && rte_ipv6_addr_eq(&l3->ipv6, ip))
			return errno_set(EEXIST);
	}

	if (nh6_lookup(iface->vrf_id, iface->id, ip) != NULL)
		return errno_set(EADDRINUSE);

	struct gr_nexthop_base base = {
		.type = GR_NH_T_L3,
		.iface_id = iface->id,
		.vrf_id = iface->vrf_id,
		.origin = GR_NH_ORIGIN_INTERNAL,
	};
	struct gr_nexthop_info_l3 l3 = {
		.af = GR_AF_IP6,
		.ipv6 = *ip,
		.prefixlen = prefixlen,
		.flags = NH_LOCAL_ADDR_FLAGS,
		.state = GR_NH_S_REACHABLE,
	};
	if ((ret = iface_get_eth_addr(iface, &l3.mac)) < 0 && errno != EOPNOTSUPP)
		return errno_set(-ret);

	if ((nh = nexthop_new(&base, &l3)) == NULL)
		return errno_set(errno);

	// join the solicited node multicast group
	rte_ipv6_solnode_from_addr(&solicited_node, ip);
	if (mcast6_addr_add(iface, &solicited_node) < 0) {
		if (errno != EOPNOTSUPP && errno != EEXIST) {
			nexthop_decref(nh);
			return errno_set(errno);
		}
	}

	ret = rib6_insert(iface->vrf_id, iface->id, ip, prefixlen, GR_NH_ORIGIN_LINK, nh);
	if (ret < 0)
		return errno_set(-ret);

	if (iface->cp_id != 0 && netlink_add_addr6(iface->cp_id, ip) < 0)
		LOG(WARNING, "add addr " IP6_F " on linux has failed (%s)", ip, strerror(errno));

	// arr_add may realloc() and free the old vector
	// Duplicate the whole vector and append to the clone.
	arr struct nexthop **nhs_copy = NULL;
	arr struct nexthop **nhs_old = addrs->nh;
	arr_cap_set(nhs_copy, arr_len(nhs_old) + 1); // avoid malloc+realloc
	arr_extend(nhs_copy, nhs_old);
	arr_add(nhs_copy, nh);
	addrs->nh = nhs_copy;
	if (nhs_old != NULL) {
		// Once all datapath workers have seen the new clone, free the old one.
		rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
		arr_free(nhs_old);
	}

	event_push(
		GR_EVENT_IP6_ADDR_ADD,
		&(struct gr_ip6_ifaddr) {
			.iface_id = iface->id,
			.addr = {*ip, prefixlen},
		}
	);

	return 0;
}

static struct api_out addr6_add(const void *request, struct api_ctx *) {
	const struct gr_ip6_addr_add_req *req = request;
	struct iface *iface;
	int ret;

	iface = iface_from_id(req->addr.iface_id);
	if (iface == NULL)
		return api_out(errno, 0, NULL);

	if ((ret = iface6_addr_add(iface, &req->addr.addr.ip, req->addr.addr.prefixlen)) < 0)
		if (ret != -EEXIST || !req->exist_ok)
			return api_out(-ret, 0, NULL);

	return api_out(0, 0, NULL);
}

int addr6_delete(uint16_t iface_id, const struct rte_ipv6_addr *ip, uint8_t prefixlen) {
	const struct iface *iface = iface_from_id(iface_id);
	struct rte_ipv6_addr solicited_node;
	struct nexthop *nh = NULL;
	struct hoplist *addrs;
	unsigned i = 0;

	if (iface == NULL)
		return -errno;
	if (ip == NULL || prefixlen > RTE_IPV6_MAX_DEPTH)
		return errno_set(EINVAL);

	addrs = &iface_addrs[iface->id];

	arr_foreach (nh, addrs->nh) {
		const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
		if (rte_ipv6_addr_eq(&l3->ipv6, ip) && l3->prefixlen == prefixlen)
			break;
		nh = NULL;
		i++;
	}
	if (nh == NULL)
		return errno_set(ENOENT);

	event_push(
		GR_EVENT_IP6_ADDR_DEL,
		&(struct gr_ip6_ifaddr) {
			.iface_id = iface->id,
			.addr = {*ip, prefixlen},
		}
	);

	nexthop_routes_cleanup(nh);
	while (nh->ref_count > 0)
		nexthop_decref(nh);

	// shift the remaining addresses
	arr_del(addrs->nh, i);
	if (arr_len(addrs->nh) == 0)
		arr_free(addrs->nh);

	// leave the solicited node multicast group
	rte_ipv6_solnode_from_addr(&solicited_node, ip);
	if (mcast6_addr_del(iface, &solicited_node) < 0) {
		if (errno != EOPNOTSUPP && errno != ENOENT)
			return errno_set(errno);
	}

	if (iface->cp_id != 0 && netlink_del_addr6(iface->cp_id, ip) < 0 && errno != EADDRNOTAVAIL)
		LOG(WARNING, "delete addr " IP6_F " on linux has failed (%s)", ip, strerror(errno));

	return 0;
}

static struct api_out addr6_del(const void *request, struct api_ctx *) {
	const struct gr_ip6_addr_del_req *req = request;
	const struct iface *iface;

	iface = iface_from_id(req->addr.iface_id);
	if (iface == NULL)
		return api_out(errno, 0, NULL);

	if (addr6_delete(iface->id, &req->addr.addr.ip, req->addr.addr.prefixlen) < 0)
		if (errno != ENOENT || !req->missing_ok)
			return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out addr6_flush(const void *request, struct api_ctx *) {
	const struct gr_ip6_addr_flush_req *req = request;
	const struct nexthop_info_l3 *l3;
	const struct iface *iface;
	struct hoplist *addrs;
	const struct nexthop *nh;
	unsigned i = 0;

	iface = iface_from_id(req->iface_id);
	if (iface == NULL)
		return api_out(errno, 0, NULL);

	addrs = &iface_addrs[iface->id];
	while (i < arr_len(addrs->nh)) {
		nh = addrs->nh[i];
		l3 = nexthop_info_l3(nh);
		if (rte_ipv6_addr_is_linklocal(&l3->ipv6)) {
			i++;
			continue;
		}
		if (addr6_delete(iface->id, &l3->ipv6, l3->prefixlen) < 0)
			return api_out(errno, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct api_out addr6_list(const void *request, struct api_ctx *ctx) {
	const struct gr_ip6_addr_list_req *req = request;
	const struct hoplist *addrs;
	const struct nexthop *nh;
	uint16_t iface_id;

	for (iface_id = 0; iface_id < GR_MAX_IFACES; iface_id++) {
		if (req->iface_id != GR_IFACE_ID_UNDEF && iface_id != req->iface_id)
			continue;
		addrs = addr6_get_all(iface_id);
		if (addrs == NULL)
			continue;
		arr_foreach (nh, addrs->nh) {
			if (req->vrf_id != GR_VRF_ID_UNDEF && nh->vrf_id != req->vrf_id)
				continue;
			const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
			struct gr_ip6_ifaddr addr = {
				.addr.ip = l3->ipv6,
				.addr.prefixlen = l3->prefixlen,
				.iface_id = nh->iface_id,
			};
			api_send(ctx, sizeof(addr), &addr);
		}
	}

	return api_out(0, 0, NULL);
}

#define GR_IPV6_ADDR_OSPF_ALL_SPF_ROUTERS RTE_IPV6(0xff02, 0, 0, 0, 0, 0, 0, 5)
#define GR_IPV6_ADDR_OSPF_ALL_DR_ROUTERS RTE_IPV6(0xff02, 0, 0, 0, 0, 0, 0, 6)
#define GR_IPV6_ADDR_ISIS_FOR_IPv6_ROUTERS RTE_IPV6(0xff02, 0, 0, 0, 0, 0, 0, 8)
#define GR_IPV6_ADDR_MLDV2 RTE_IPV6(0xff02, 0, 0, 0, 0, 0, 0, 0x16)

static const struct rte_ipv6_addr well_known_mcast_addrs[] = {
	RTE_IPV6_ADDR_ALLNODES_IFACE_LOCAL,
	RTE_IPV6_ADDR_ALLNODES_LINK_LOCAL,
	RTE_IPV6_ADDR_ALLROUTERS_IFACE_LOCAL,
	RTE_IPV6_ADDR_ALLROUTERS_LINK_LOCAL,
	RTE_IPV6_ADDR_ALLROUTERS_SITE_LOCAL,
	GR_IPV6_ADDR_OSPF_ALL_SPF_ROUTERS,
	GR_IPV6_ADDR_OSPF_ALL_DR_ROUTERS,
	GR_IPV6_ADDR_ISIS_FOR_IPv6_ROUTERS,
	GR_IPV6_ADDR_MLDV2,
};

static void ip6_iface_llocal_init(const struct iface *iface) {
	struct rte_ipv6_addr link_local;
	struct rte_ether_addr mac;
	unsigned i;

	if (iface_get_eth_addr(iface, &mac) < 0)
		return;

	rte_ipv6_llocal_from_ethernet(&link_local, &mac);
	if (iface6_addr_add(iface, &link_local, 64) < 0)
		errno_log(errno, "iface_addr_add");

	for (i = 0; i < ARRAY_DIM(well_known_mcast_addrs); i++) {
		if (mcast6_addr_add(iface, &well_known_mcast_addrs[i]) < 0)
			LOG(INFO, "%s: mcast_addr_add: %s", iface->name, strerror(errno));
	}
}

static void ip6_iface_addrs_flush(const struct iface *iface) {
	const struct nexthop_info_l3 *l3;
	const struct nexthop *nh;
	struct hoplist *addrs;

	addrs = &iface_addrs[iface->id];
	while (arr_len(addrs->nh) > 0) {
		nh = addrs->nh[arr_len(addrs->nh) - 1];
		l3 = nexthop_info_l3(nh);
		addr6_delete(iface->id, &l3->ipv6, l3->prefixlen);
	}
	addrs = &iface_mcast_addrs[iface->id];
	while (arr_len(addrs->nh) > 0) {
		nh = addrs->nh[arr_len(addrs->nh) - 1];
		l3 = nexthop_info_l3(nh);
		mcast6_addr_del(iface, &l3->ipv6);
	}
}

static void ip6_iface_event_handler(uint32_t event, const void *obj) {
	const struct iface *iface = obj;
	const struct nexthop *nh;
	struct hoplist *addrs;

	switch (event) {
	case GR_EVENT_IFACE_POST_ADD:
		if (iface->mode == GR_IFACE_MODE_VRF)
			ip6_iface_llocal_init(iface);
		break;
	case GR_EVENT_IFACE_POST_RECONFIG:
		if (iface->mode != GR_IFACE_MODE_VRF) {
			// changing mode from VRF -> !VRF
			ip6_iface_addrs_flush(iface);
		} else if (arr_len(iface_addrs[iface->id].nh) == 0) {
			// changing mode from !VRF -> VRF
			ip6_iface_llocal_init(iface);
		} else if (iface_addrs[iface->id].nh[0]->vrf_id != iface->vrf_id) {
			// changing to a different VRF
			ip6_iface_addrs_flush(iface);
			ip6_iface_llocal_init(iface);
		}
		break;
	case GR_EVENT_IFACE_PRE_REMOVE:
		ip6_iface_addrs_flush(iface);
		break;
	case GR_EVENT_IFACE_STATUS_UP:
	case GR_EVENT_IFACE_MAC_CHANGE:
		addrs = &iface_addrs[iface->id];
		arr_foreach (nh, addrs->nh) {
			if (nh6_advertise(nh, NULL) < 0)
				LOG(WARNING, "nh6_advertise: %s", strerror(errno));
		}
		break;
	default:
		break;
	}
}

static void addr6_init(struct event_base *) {
	iface_addrs = rte_calloc(
		__func__, GR_MAX_IFACES, sizeof(*iface_addrs), RTE_CACHE_LINE_SIZE
	);
	if (iface_addrs == NULL)
		ABORT("rte_calloc(iface_addrs)");
	iface_mcast_addrs = rte_calloc(
		__func__, GR_MAX_IFACES, sizeof(*iface_mcast_addrs), RTE_CACHE_LINE_SIZE
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

static struct module addr6_module = {
	.name = "ip6_address",
	.init = addr6_init,
	.fini = addr6_fini,
};

RTE_INIT(address_constructor) {
	api_handler(GR_IP6_ADDR_ADD, addr6_add);
	api_handler(GR_IP6_ADDR_DEL, addr6_del);
	api_handler(GR_IP6_ADDR_FLUSH, addr6_flush);
	api_handler(GR_IP6_ADDR_LIST, addr6_list);
	module_register(&addr6_module);
	event_subscribe(GR_EVENT_IFACE_POST_ADD, ip6_iface_event_handler);
	event_subscribe(GR_EVENT_IFACE_POST_RECONFIG, ip6_iface_event_handler);
	event_subscribe(GR_EVENT_IFACE_PRE_REMOVE, ip6_iface_event_handler);
	event_subscribe(GR_EVENT_IFACE_STATUS_UP, ip6_iface_event_handler);
	event_subscribe(GR_EVENT_IFACE_MAC_CHANGE, ip6_iface_event_handler);
	event_serializer(GR_EVENT_IP6_ADDR_ADD, NULL);
	event_serializer(GR_EVENT_IP6_ADDR_DEL, NULL);
}
