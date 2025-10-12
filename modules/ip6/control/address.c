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
#include <gr_rcu.h>
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
	const struct nexthop_info_l3 *l3;
	struct nexthop *pref = NULL, *nh;

	if (addrs == NULL)
		return NULL;

	gr_vec_foreach (nh, addrs->nh) {
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

	gr_vec_foreach (nh, addrs->nh) {
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

	if (iface_id >= MAX_IFACES)
		return NULL;

	maddrs = &iface_mcast_addrs[iface_id];
	gr_vec_foreach (nh, maddrs->nh) {
		l3 = nexthop_info_l3(nh);
		if (rte_ipv6_addr_eq(&l3->ipv6, mcast))
			return nh;
	}

	return NULL;
}

static int mcast6_addr_add(const struct iface *iface, const struct rte_ipv6_addr *ip) {
	struct hoplist *maddrs = &iface_mcast_addrs[iface->id];
	struct rte_ether_addr mac;
	struct nexthop *nh;

	LOG(INFO, "%s: joining multicast group " IP6_F, iface->name, ip);

	gr_vec_foreach (nh, maddrs->nh) {
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
		rte_ether_mcast_from_ipv6(&l3.mac, ip);

		if ((nh = nexthop_new(&base, &l3)) == NULL)
			return errno_set(errno);

		mac = l3.mac;
	} else {
		struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
		mac = l3->mac;
	}

	nexthop_incref(nh);

	// gr_vec_add may realloc() and free the old vector
	// Duplicate the whole vector and append to the clone.
	gr_vec struct nexthop **nhs_copy = NULL;
	gr_vec struct nexthop **nhs_old = maddrs->nh;
	gr_vec_cap_set(nhs_copy, gr_vec_len(nhs_old) + 1); // avoid malloc+realloc
	gr_vec_extend(nhs_copy, nhs_old);
	gr_vec_add(nhs_copy, nh);
	maddrs->nh = nhs_copy;
	if (nhs_old != NULL) {
		// Once all datapath workers have seen the new clone, free the old one.
		rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
		gr_vec_free(nhs_old);
	}

	// add ethernet filter
	return iface_add_eth_addr(iface->id, &mac);
}

static int mcast6_addr_del(const struct iface *iface, const struct rte_ipv6_addr *ip) {
	struct hoplist *maddrs = &iface_mcast_addrs[iface->id];
	const struct nexthop_info_l3 *l3;
	struct nexthop *nh = NULL;
	unsigned i = 0;
	int ret = 0;

	gr_vec_foreach (nh, maddrs->nh) {
		l3 = nexthop_info_l3(nh);
		if (rte_ipv6_addr_eq(&l3->ipv6, ip))
			break;
		nh = NULL;
		i++;
	}
	if (nh == NULL)
		return errno_set(ENOENT);

	// shift remaining addresses
	gr_vec_del(maddrs->nh, i);

	if (nh->ref_count == 1) {
		LOG(INFO, "%s: leaving multicast group " IP6_F, iface->name, ip);
		// remove ethernet filter
		l3 = nexthop_info_l3(nh);
		ret = iface_del_eth_addr(iface->id, &l3->mac);
	}
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

	addrs = &iface_addrs[iface->id];

	gr_vec_foreach (nh, addrs->nh) {
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
		.flags = GR_NH_F_LOCAL | GR_NH_F_LINK | GR_NH_F_STATIC,
		.state = GR_NH_S_REACHABLE,
	};
	if ((ret = iface_get_eth_addr(iface->id, &l3.mac)) < 0 && errno != EOPNOTSUPP)
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

	// gr_vec_add may realloc() and free the old vector
	// Duplicate the whole vector and append to the clone.
	gr_vec struct nexthop **nhs_copy = NULL;
	gr_vec struct nexthop **nhs_old = addrs->nh;
	gr_vec_cap_set(nhs_copy, gr_vec_len(nhs_old) + 1); // avoid malloc+realloc
	gr_vec_extend(nhs_copy, nhs_old);
	gr_vec_add(nhs_copy, nh);
	addrs->nh = nhs_copy;
	if (nhs_old != NULL) {
		// Once all datapath workers have seen the new clone, free the old one.
		rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
		gr_vec_free(nhs_old);
	}

	gr_event_push(
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

static int
iface6_addr_del(const struct iface *iface, const struct rte_ipv6_addr *ip, uint8_t prefixlen) {
	struct rte_ipv6_addr solicited_node;
	struct nexthop *nh = NULL;
	struct hoplist *addrs;
	unsigned i = 0;

	if (iface == NULL || ip == NULL || prefixlen > RTE_IPV6_MAX_DEPTH)
		return errno_set(EINVAL);

	addrs = &iface_addrs[iface->id];

	gr_vec_foreach (nh, addrs->nh) {
		const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
		if (rte_ipv6_addr_eq(&l3->ipv6, ip) && l3->prefixlen == prefixlen)
			break;
		nh = NULL;
		i++;
	}
	if (nh == NULL)
		return errno_set(ENOENT);

	gr_event_push(
		GR_EVENT_IP6_ADDR_DEL,
		&(struct gr_ip6_ifaddr) {
			.iface_id = iface->id,
			.addr = {*ip, prefixlen},
		}
	);

	rib6_cleanup(nh);

	// shift the remaining addresses
	gr_vec_del(addrs->nh, i);

	// leave the solicited node multicast group
	rte_ipv6_solnode_from_addr(&solicited_node, ip);
	if (mcast6_addr_del(iface, &solicited_node) < 0) {
		if (errno != EOPNOTSUPP && errno != ENOENT)
			return errno_set(errno);
	}

	return 0;
}

static struct api_out addr6_del(const void *request, struct api_ctx *) {
	const struct gr_ip6_addr_del_req *req = request;
	const struct iface *iface;

	iface = iface_from_id(req->addr.iface_id);
	if (iface == NULL)
		return api_out(errno, 0, NULL);

	if (iface6_addr_del(iface, &req->addr.addr.ip, req->addr.addr.prefixlen) < 0)
		if (errno != ENOENT || !req->missing_ok)
			return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out addr6_list(const void *request, struct api_ctx *ctx) {
	const struct gr_ip6_addr_list_req *req = request;
	const struct hoplist *addrs;
	const struct nexthop *nh;
	uint16_t iface_id;

	for (iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		if (req->iface_id != GR_IFACE_ID_UNDEF && iface_id != req->iface_id)
			continue;
		addrs = addr6_get_all(iface_id);
		if (addrs == NULL)
			continue;
		gr_vec_foreach (nh, addrs->nh) {
			if (req->vrf_id != GR_VRF_ID_ALL && nh->vrf_id != req->vrf_id)
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

static const struct rte_ipv6_addr well_known_mcast_addrs[] = {
	RTE_IPV6_ADDR_ALLNODES_IFACE_LOCAL,
	RTE_IPV6_ADDR_ALLNODES_LINK_LOCAL,
	RTE_IPV6_ADDR_ALLROUTERS_IFACE_LOCAL,
	RTE_IPV6_ADDR_ALLROUTERS_LINK_LOCAL,
	RTE_IPV6_ADDR_ALLROUTERS_SITE_LOCAL,
};

static void ip6_iface_event_handler(uint32_t event, const void *obj) {
	const struct nexthop_info_l3 *l3;
	const struct iface *iface = obj;
	struct rte_ipv6_addr link_local;
	struct rte_ether_addr mac;
	const struct nexthop *nh;
	unsigned i;

	switch (event) {
	case GR_EVENT_IFACE_POST_ADD:
		if (iface->type == GR_IFACE_TYPE_LOOPBACK)
			break;
		if (iface_get_eth_addr(iface->id, &mac) == 0) {
			rte_ipv6_llocal_from_ethernet(&link_local, &mac);
			if (iface6_addr_add(iface, &link_local, 64) < 0)
				errno_log(errno, "iface_addr_add");
		}
		for (i = 0; i < ARRAY_DIM(well_known_mcast_addrs); i++) {
			if (mcast6_addr_add(iface, &well_known_mcast_addrs[i]) < 0)
				LOG(INFO, "%s: mcast_addr_add: %s", iface->name, strerror(errno));
		}
		break;
	case GR_EVENT_IFACE_PRE_REMOVE:
		struct hoplist *addrs = &iface_addrs[iface->id];
		while (gr_vec_len(addrs->nh) > 0) {
			nh = addrs->nh[0];
			l3 = (const struct nexthop_info_l3 *)nh->info;
			iface6_addr_del(iface, &l3->ipv6, l3->prefixlen);
		}
		gr_vec_free(addrs->nh);
		addrs = &iface_mcast_addrs[iface->id];
		while (gr_vec_len(addrs->nh) > 0) {
			nh = addrs->nh[0];
			l3 = (const struct nexthop_info_l3 *)nh->info;
			mcast6_addr_del(iface, &l3->ipv6);
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
};

static struct gr_event_subscription iface_event_subscription = {
	.callback = ip6_iface_event_handler,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IFACE_POST_ADD,
		GR_EVENT_IFACE_PRE_REMOVE,
	},
};
static struct gr_event_serializer iface_addr_serializer = {
	.size = sizeof(struct gr_ip6_ifaddr),
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IP6_ADDR_ADD,
		GR_EVENT_IP6_ADDR_DEL,
	},
};

RTE_INIT(address_constructor) {
	gr_register_api_handler(&addr6_add_handler);
	gr_register_api_handler(&addr6_del_handler);
	gr_register_api_handler(&addr6_list_handler);
	gr_register_module(&addr6_module);
	gr_event_subscribe(&iface_event_subscription);
	gr_event_register_serializer(&iface_addr_serializer);
}
