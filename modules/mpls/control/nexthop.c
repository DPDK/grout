// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#include "mpls.h"

#include <gr_mpls.h>

static int mpls_nh_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_mpls *priv = nexthop_info_mpls(nh);
	const struct gr_nexthop_info_mpls *pub = info;
	struct gr_nexthop_info_l3 l3_info;
	struct nexthop *via_nh, *old_via;

	if (pub->n_labels > GR_MPLS_MAX_LABELS)
		return errno_set(EINVAL);

	for (uint8_t i = 0; i < pub->n_labels; i++) {
		if (pub->labels[i] > GR_MPLS_LABEL_MAX)
			return errno_set(EINVAL);
		if (pub->labels[i] == GR_MPLS_LABEL_IMPLICIT_NULL)
			return errno_set(EINVAL);
	}

	switch (pub->payload_af) {
	case GR_AF_UNSPEC:
	case GR_AF_IP4:
	case GR_AF_IP6:
		break;
	default:
		return errno_set(EINVAL);
	}

	if (pub->via.af == GR_AF_UNSPEC) {
		// No via: pop and hand the payload to the local IP stack. Used for
		// the reserved explicit/implicit NULL labels (RFC 3032).
		via_nh = NULL;
	} else if (pub->via.af == GR_AF_IP4 || pub->via.af == GR_AF_IP6) {
		via_nh = nexthop_lookup_l3(pub->via.af, nh->vrf_id, nh->iface_id, &pub->via.addr);
		if (via_nh == NULL) {
			l3_info = (struct gr_nexthop_info_l3) {.af = pub->via.af};
			if (pub->via.af == GR_AF_IP4)
				l3_info.ipv4 = pub->via.ipv4;
			else
				l3_info.ipv6 = pub->via.ipv6;

			via_nh = nexthop_new(
				&(struct gr_nexthop_base) {
					.type = GR_NH_T_L3,
					.iface_id = nh->iface_id,
					.vrf_id = nh->vrf_id,
					.origin = GR_NH_ORIGIN_INTERNAL,
				},
				&l3_info
			);
			if (via_nh == NULL)
				return -errno;
		} else {
			nexthop_incref(via_nh);
		}
	} else {
		return errno_set(EAFNOSUPPORT);
	}

	old_via = priv->via_nh;
	priv->base = *pub;
	priv->via_nh = via_nh;
	if (old_via != NULL)
		nexthop_decref(old_via);

	return 0;
}

static void mpls_nh_free(struct nexthop *nh) {
	struct nexthop_info_mpls *priv = nexthop_info_mpls(nh);
	if (priv->via_nh != NULL)
		nexthop_decref(priv->via_nh);
	priv->via_nh = NULL;
}

static void mpls_nh_remove_via_cb(struct nexthop *nh, void *dying) {
	if (nh->type != GR_NH_T_MPLS)
		return;
	struct nexthop_info_mpls *priv = nexthop_info_mpls(nh);
	if (priv->via_nh == dying)
		priv->via_nh = NULL;
}

static void mpls_nh_remove_references(struct nexthop *dying) {
	nexthop_iter(mpls_nh_remove_via_cb, dying);
}

static bool mpls_nh_equal(const struct nexthop *a, const struct nexthop *b) {
	const struct nexthop_info_mpls *ma = nexthop_info_mpls(a);
	const struct nexthop_info_mpls *mb = nexthop_info_mpls(b);

	if (ma->n_labels != mb->n_labels)
		return false;
	if (ma->payload_af != mb->payload_af)
		return false;
	if (ma->via_nh != mb->via_nh)
		return false;
	return memcmp(ma->labels, mb->labels, ma->n_labels * sizeof(ma->labels[0])) == 0;
}

static struct gr_nexthop *mpls_nh_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_mpls *priv = nexthop_info_mpls(nh);
	struct gr_nexthop_info_mpls *pub_info;
	struct gr_nexthop *pub;

	*len = sizeof(*pub) + sizeof(*pub_info);
	pub = calloc(1, *len);
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	pub_info = (struct gr_nexthop_info_mpls *)pub->info;
	*pub_info = priv->base;

	return pub;
}

static struct nexthop_type_ops mpls_nh_ops = {
	.import_info = mpls_nh_import_info,
	.free = mpls_nh_free,
	.remove_references = mpls_nh_remove_references,
	.equal = mpls_nh_equal,
	.to_api = mpls_nh_to_api,
};

RTE_INIT(mpls_nexthop_init) {
	nexthop_type_ops_register(GR_NH_T_MPLS, &mpls_nh_ops);
}

#ifdef __GROUT_UNIT_TEST__
bool mpls_nh_equal_test(const struct nexthop *a, const struct nexthop *b);
bool mpls_nh_equal_test(const struct nexthop *a, const struct nexthop *b) {
	return mpls_nh_equal(a, b);
}
#endif
