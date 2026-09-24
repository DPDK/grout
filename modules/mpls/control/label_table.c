// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "event.h"
#include "log.h"
#include "mpls.h"

#include <gr_mpls.h>

#include <rte_malloc.h>

LOG_TYPE("mpls");

#define MPLS_LFIB_SIZE (GR_MPLS_LABEL_MAX + 1)

static struct nexthop **get_lfib(uint16_t vrf_id) {
	struct iface *iface = get_vrf_iface(vrf_id);
	if (iface == NULL)
		return NULL;
	struct nexthop **lfib = iface_info_vrf(iface)->fib_mpls;
	if (lfib == NULL)
		return errno_set_null(ENONET);
	return lfib;
}

const struct nexthop *mpls_fib_lookup(uint16_t vrf_id, uint32_t label) {
	struct nexthop **lfib = get_lfib(vrf_id);

	if (lfib == NULL || label > GR_MPLS_LABEL_MAX)
		return NULL;

	return lfib[label];
}

int mpls_rib_insert(
	uint16_t vrf_id,
	uint32_t label,
	struct nexthop *nh,
	gr_nh_origin_t origin,
	bool exist_ok
) {
	struct nexthop **lfib = get_lfib(vrf_id);
	struct nexthop *existing;

	if (lfib == NULL)
		return -errno;
	if (label > GR_MPLS_LABEL_MAX)
		return errno_set(EINVAL);

	existing = lfib[label];
	if (existing != NULL) {
		if (!exist_ok)
			return errno_set(EEXIST);
		if (existing == nh)
			return 0;
	}

	nexthop_incref(nh);
	lfib[label] = nh;

	if (origin != GR_NH_ORIGIN_INTERNAL) {
		event_push(
			GR_EVENT_MPLS_ROUTE_ADD,
			&(const struct gr_mpls_label_route) {
				.vrf_id = vrf_id,
				.in_label = label,
				.nh_id = nh->nh_id,
				.origin = origin,
			}
		);
	}

	if (existing != NULL)
		nexthop_decref(existing);

	return 0;
}

int mpls_rib_delete(uint16_t vrf_id, uint32_t label, bool missing_ok) {
	struct nexthop **lfib = get_lfib(vrf_id);
	struct nexthop *nh;

	if (lfib == NULL)
		return -errno;
	if (label > GR_MPLS_LABEL_MAX)
		return errno_set(EINVAL);

	nh = lfib[label];
	if (nh == NULL) {
		if (missing_ok)
			return 0;
		return errno_set(ENOENT);
	}

	lfib[label] = NULL;

	if (nh->origin != GR_NH_ORIGIN_INTERNAL) {
		event_push(
			GR_EVENT_MPLS_ROUTE_DEL,
			&(const struct gr_mpls_label_route) {
				.vrf_id = vrf_id,
				.in_label = label,
				.nh_id = nh->nh_id,
				.origin = nh->origin,
			}
		);
	}

	nexthop_decref(nh);

	return 0;
}

int mpls_rib_iter(uint16_t vrf_id, mpls_rib_iter_cb cb, void *priv) {
	if (vrf_id != GR_VRF_ID_UNDEF) {
		struct nexthop **lfib = get_lfib(vrf_id);
		if (lfib == NULL)
			return -errno;
		for (uint32_t i = 0; i < MPLS_LFIB_SIZE; i++) {
			if (lfib[i] == NULL)
				continue;
			int ret = cb(vrf_id, i, lfib[i], priv);
			if (ret < 0)
				return ret;
		}
	} else {
		for (uint16_t v = 1; v < GR_MAX_IFACES; v++) {
			struct iface *iface = iface_from_id(v);
			if (iface == NULL || iface->type != GR_IFACE_TYPE_VRF)
				continue;
			struct nexthop **lfib = iface_info_vrf(iface)->fib_mpls;
			if (lfib == NULL)
				continue;
			for (uint32_t i = 0; i < MPLS_LFIB_SIZE; i++) {
				if (lfib[i] == NULL)
					continue;
				int ret = cb(v, i, lfib[i], priv);
				if (ret < 0)
					return ret;
			}
		}
	}
	return 0;
}

static int mpls_fib_init(struct iface *vrf) {
	struct nexthop **lfib;

	lfib = rte_zmalloc("mpls_lfib", MPLS_LFIB_SIZE * sizeof(*lfib), RTE_CACHE_LINE_SIZE);
	if (lfib == NULL)
		return errno_log(rte_errno, "rte_zmalloc(mpls_lfib)");

	iface_info_vrf(vrf)->fib_mpls = lfib;

	return 0;
}

static int mpls_fib_reconfig(struct iface *) {
	return 0;
}

static void mpls_fib_fini(struct iface *vrf) {
	struct nexthop **lfib = iface_info_vrf(vrf)->fib_mpls;
	if (lfib == NULL)
		return;

	for (uint32_t i = 0; i < MPLS_LFIB_SIZE; i++) {
		if (lfib[i] != NULL)
			nexthop_decref(lfib[i]);
	}

	rte_free(lfib);
	iface_info_vrf(vrf)->fib_mpls = NULL;
}

static const struct vrf_fib_ops mpls_fib_ops = {
	.init = mpls_fib_init,
	.reconfig = mpls_fib_reconfig,
	.fini = mpls_fib_fini,
};

RTE_INIT(mpls_label_table_init) {
	vrf_fib_ops_register(GR_AF_MPLS, &mpls_fib_ops);
}
