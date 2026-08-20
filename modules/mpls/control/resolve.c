// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "l3.h"
#include "log.h"
#include "mpls.h"
#include "mpls_datapath.h"

#include <gr_mpls.h>

LOG_TYPE("mpls");

static void mpls_resolve_cb(void *obj, uintptr_t, const struct control_queue_drain *drain) {
	struct rte_mbuf *m = obj;
	struct nexthop_info_l3 *l3;
	struct nexthop *nh;

	nh = (struct nexthop *)l3_mbuf_data(m)->nh;

	if (drain != NULL) {
		switch (drain->event) {
		case GR_EVENT_IFACE_REMOVE:
			if (mbuf_data(m)->iface == drain->obj)
				goto free;
			break;
		case GR_EVENT_NEXTHOP_DELETE:
			if (nh == drain->obj)
				goto free;
			if (mpls_hold_mbuf_data(m)->mpls_nh == drain->obj)
				goto free;
			break;
		}
	}

	l3 = nexthop_info_l3(nh);

	if (l3->state == GR_NH_S_REACHABLE) {
		if (mpls_resubmit_cb(m, nh) < 0)
			goto free;
		return;
	}

	if (l3->held_pkts < nh_conf.max_held_pkts) {
		queue_mbuf_data(m)->next = NULL;
		if (l3->held_pkts_head == NULL)
			l3->held_pkts_head = m;
		else
			queue_mbuf_data(l3->held_pkts_tail)->next = m;
		l3->held_pkts_tail = m;
		l3->held_pkts++;
		if (l3->state != GR_NH_S_PENDING) {
			const struct nexthop_af_ops *ops = nexthop_af_ops_from_nh(nh);
			if (ops != NULL)
				ops->solicit(nh);
			l3->state = GR_NH_S_PENDING;
		}
		return;
	}

free:
	rte_pktmbuf_free(m);
}

static int mpls_solicit(struct nexthop *nh) {
	const struct nexthop_af_ops *ops = nexthop_af_ops_from_nh(nh);
	if (ops != NULL)
		return ops->solicit(nh);
	return errno_set(ENOTSUP);
}

static void mpls_rib_cleanup(struct nexthop *nh) {
	for (uint16_t v = 1; v < GR_MAX_IFACES; v++) {
		struct iface *iface = iface_from_id(v);
		if (iface == NULL || iface->type != GR_IFACE_TYPE_VRF)
			continue;
		struct nexthop **lfib = iface_info_vrf(iface)->fib_mpls;
		if (lfib == NULL)
			continue;
		for (uint32_t i = 0; i <= GR_MPLS_LABEL_MAX; i++) {
			if (lfib[i] == nh) {
				lfib[i] = NULL;
				nexthop_decref(nh);
			}
		}
	}
}

static struct nexthop_af_ops mpls_af_ops = {
	.resolve = mpls_resolve_cb,
	.solicit = mpls_solicit,
	.resubmit = mpls_resubmit_cb,
	.cleanup_routes = mpls_rib_cleanup,
};

RTE_INIT(mpls_resolve_constructor) {
	nexthop_af_ops_register(GR_AF_MPLS, &mpls_af_ops);
}
