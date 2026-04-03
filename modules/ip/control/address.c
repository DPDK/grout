// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "event.h"
#include "iface.h"
#include "ip4.h"
#include "ip4_datapath.h"
#include "log.h"
#include "module.h"
#include "netlink.h"
#include "rcu.h"
#include "vec.h"

#include <gr_ip4.h>
#include <gr_net_types.h>

#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

LOG_TYPE("address");

static struct hoplist *iface_addrs;

struct hoplist *addr4_get_all(uint16_t iface_id) {
	struct hoplist *addrs;

	if (iface_id >= GR_MAX_IFACES)
		return errno_set_null(ENODEV);

	addrs = &iface_addrs[iface_id];
	if (vec_len(addrs->nh) == 0)
		return errno_set_null(ENOENT);

	return addrs;
}

struct nexthop *addr4_get_preferred(uint16_t iface_id, ip4_addr_t dst) {
	struct hoplist *addrs = addr4_get_all(iface_id);
	const struct nexthop_info_l3 *l3;
	struct nexthop *nh;

	if (addrs == NULL)
		return NULL;

	vec_foreach (nh, addrs->nh) {
		l3 = nexthop_info_l3(nh);
		if (ip4_addr_same_subnet(dst, l3->ipv4, l3->prefixlen))
			return nh;
	}

	return addrs->nh[0];
}

int addr4_add(uint16_t iface_id, ip4_addr_t ip, uint16_t prefixlen, gr_nh_origin_t origin) {
	const struct iface *iface;
	struct hoplist *ifaddrs;
	struct nexthop *nh;
	int ret;

	iface = iface_from_id(iface_id);
	if (iface == NULL)
		return -errno;

	if (iface->mode != GR_IFACE_MODE_VRF)
		return errno_set(EMEDIUMTYPE);

	ifaddrs = &iface_addrs[iface->id];

	vec_foreach (nh, ifaddrs->nh) {
		const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
		if (ip == l3->ipv4 && prefixlen == l3->prefixlen)
			return errno_set(EEXIST);
	}

	if (nh4_lookup(iface->vrf_id, ip) != NULL)
		return errno_set(EADDRINUSE);

	struct gr_nexthop_base base = {
		.type = GR_NH_T_L3,
		.origin = GR_NH_ORIGIN_INTERNAL,
		.iface_id = iface->id,
		.vrf_id = iface->vrf_id,
	};
	struct gr_nexthop_info_l3 l3 = {
		.af = GR_AF_IP4,
		.ipv4 = ip,
		.prefixlen = prefixlen,
		.flags = NH_LOCAL_ADDR_FLAGS,
		.state = GR_NH_S_REACHABLE,
	};
	if (iface_get_eth_addr(iface, &l3.mac) < 0 && errno != EOPNOTSUPP)
		return -errno;

	if ((nh = nexthop_new(&base, &l3)) == NULL)
		return -errno;

	ret = rib4_insert(iface->vrf_id, ip, prefixlen, origin, nh);
	if (ret < 0) {
		nexthop_decref(nh);
		return ret;
	}

	// vec_add may realloc() and free the old vector
	// Duplicate the whole vector and append to the clone.
	vec struct nexthop **nhs_copy = NULL;
	vec struct nexthop **nhs_old = ifaddrs->nh;
	vec_cap_set(nhs_copy, vec_len(nhs_old) + 1); // avoid malloc+realloc
	vec_extend(nhs_copy, nhs_old);
	vec_add(nhs_copy, nh);
	ifaddrs->nh = nhs_copy;
	if (nhs_old != NULL) {
		// Once all datapath workers have seen the new clone, free the old one.
		rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
		vec_free(nhs_old);
	}

	if (iface->cp_id != 0 && netlink_add_addr4(iface->cp_id, ip) < 0)
		LOG(WARNING, "add addr " IP4_F " on linux has failed (%s)", &ip, strerror(errno));

	event_push(
		GR_EVENT_IP_ADDR_ADD,
		&(struct gr_ip4_ifaddr) {
			.addr = {ip, prefixlen},
			.iface_id = iface_id,
		}
	);

	return 0;
}

static struct api_out addr_add(const void *request, struct api_ctx *) {
	const struct gr_ip4_addr_add_req *req = request;
	int ret = addr4_add(
		req->addr.iface_id, req->addr.addr.ip, req->addr.addr.prefixlen, GR_NH_ORIGIN_LINK
	);
	if (ret < 0) {
		if (errno != EEXIST || !req->exist_ok)
			return api_out(errno, 0, NULL);
	}
	return api_out(0, 0, NULL);
}

int addr4_delete(uint16_t iface_id, ip4_addr_t ip, uint16_t prefixlen) {
	const struct iface *iface;
	struct hoplist *addrs;
	struct nexthop *nh;
	unsigned i = 0;

	if ((addrs = addr4_get_all(iface_id)) == NULL)
		return -errno;

	vec_foreach (nh, addrs->nh) {
		const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
		if (l3->ipv4 == ip && l3->prefixlen == prefixlen) {
			break;
		}
		nh = NULL;
		i++;
	}
	if (nh == NULL)
		return errno_set(ENOENT);

	event_push(
		GR_EVENT_IP_ADDR_DEL,
		&(struct gr_ip4_ifaddr) {
			.addr = {ip, prefixlen},
			.iface_id = iface_id,
		}
	);

	nexthop_routes_cleanup(nh);
	while (nh->ref_count > 0)
		nexthop_decref(nh);

	vec_del(addrs->nh, i);
	if (vec_len(addrs->nh) == 0)
		vec_free(addrs->nh);

	iface = iface_from_id(iface_id);
	if (iface && iface->cp_id != 0) {
		if (netlink_del_addr4(iface->cp_id, ip) < 0)
			LOG(WARNING,
			    "delete addr " IP4_F " on linux has failed (%s)",
			    &ip,
			    strerror(errno));
	}

	return 0;
}

static struct api_out addr_del(const void *request, struct api_ctx *) {
	const struct gr_ip4_addr_del_req *req = request;
	if (addr4_delete(req->addr.iface_id, req->addr.addr.ip, req->addr.addr.prefixlen) < 0) {
		if (errno != ENOENT || !req->missing_ok)
			return api_out(errno, 0, NULL);
	}
	return api_out(0, 0, NULL);
}

static struct api_out addr_flush(const void *request, struct api_ctx *) {
	const struct gr_ip4_addr_flush_req *req = request;
	struct nexthop_info_l3 *l3;
	struct hoplist *ifaddrs;

	ifaddrs = addr4_get_all(req->iface_id);
	if (ifaddrs == NULL) {
		if (errno == ENOENT)
			return api_out(0, 0, NULL);
		return api_out(errno, 0, NULL);
	}

	while (vec_len(ifaddrs->nh) > 0) {
		l3 = nexthop_info_l3(ifaddrs->nh[vec_len(ifaddrs->nh) - 1]);
		if (addr4_delete(req->iface_id, l3->ipv4, l3->prefixlen) < 0)
			return api_out(errno, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct api_out addr_list(const void *request, struct api_ctx *ctx) {
	const struct gr_ip4_addr_list_req *req = request;
	const struct hoplist *addrs;
	const struct nexthop *nh;
	uint16_t iface_id;

	for (iface_id = 0; iface_id < GR_MAX_IFACES; iface_id++) {
		if (req->iface_id != GR_IFACE_ID_UNDEF && iface_id != req->iface_id)
			continue;
		addrs = addr4_get_all(iface_id);
		if (addrs == NULL)
			continue;
		vec_foreach (nh, addrs->nh) {
			if (req->vrf_id != GR_VRF_ID_UNDEF && nh->vrf_id != req->vrf_id)
				continue;
			const struct nexthop_info_l3 *l3 = nexthop_info_l3(nh);
			struct gr_ip4_ifaddr addr = {
				.addr.ip = l3->ipv4,
				.addr.prefixlen = l3->prefixlen,
				.iface_id = iface_id,
			};
			api_send(ctx, sizeof(addr), &addr);
		}
	}

	return api_out(0, 0, NULL);
}

static void iface_event_cb(uint32_t event, const void *obj) {
	const struct iface *iface = obj;
	struct nexthop_info_l3 *l3;
	struct hoplist *ifaddrs;

	ifaddrs = addr4_get_all(iface->id);
	if (ifaddrs == NULL || vec_len(ifaddrs->nh) == 0)
		return;

	if (event == GR_EVENT_IFACE_POST_RECONFIG) {
		if (iface->mode == GR_IFACE_MODE_VRF && iface->vrf_id == ifaddrs->nh[0]->vrf_id)
			return;
	}

	// interface is either being deleted, mode changed to !VRF, or changed to another VRF
	// delete all configured addresses
	while (vec_len(ifaddrs->nh) > 0) {
		l3 = nexthop_info_l3(ifaddrs->nh[vec_len(ifaddrs->nh) - 1]);
		addr4_delete(iface->id, l3->ipv4, l3->prefixlen);
	}
}

static void iface_up_cb(uint32_t /*event*/, const void *obj) {
	const struct iface *iface = obj;
	struct hoplist *ifaddrs = addr4_get_all(iface->id);

	if (ifaddrs == NULL)
		return;

	vec_foreach (struct nexthop *nh, ifaddrs->nh)
		arp_output_request_solicit(nh);
}

static void addr_init(struct event_base *) {
	iface_addrs = rte_calloc(
		__func__, GR_MAX_IFACES, sizeof(struct hoplist), RTE_CACHE_LINE_SIZE
	);
	if (iface_addrs == NULL)
		ABORT("rte_calloc(addrs)");
}

static void addr_fini(struct event_base *) {
	rte_free(iface_addrs);
	iface_addrs = NULL;
}

static struct module addr_module = {
	.name = "ip_address",
	.init = addr_init,
	.fini = addr_fini,
};

RTE_INIT(address_constructor) {
	api_handler(GR_IP4_ADDR_ADD, addr_add);
	api_handler(GR_IP4_ADDR_DEL, addr_del);
	api_handler(GR_IP4_ADDR_FLUSH, addr_flush);
	api_handler(GR_IP4_ADDR_LIST, addr_list);
	module_register(&addr_module);
	event_subscribe(GR_EVENT_IFACE_POST_RECONFIG, iface_event_cb);
	event_subscribe(GR_EVENT_IFACE_PRE_REMOVE, iface_event_cb);
	event_subscribe(GR_EVENT_IFACE_STATUS_UP, iface_up_cb);
	event_subscribe(GR_EVENT_IFACE_MAC_CHANGE, iface_up_cb);
	event_serializer(GR_EVENT_IP_ADDR_ADD, NULL);
	event_serializer(GR_EVENT_IP_ADDR_DEL, NULL);
}
