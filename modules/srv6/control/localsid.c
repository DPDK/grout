// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_infra.h>
#include <gr_ip4_control.h>
#include <gr_ip6_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_srv6.h>
#include <gr_srv6_nexthop.h>

static bool srv6_local_nh_equal(const struct nexthop *a, const struct nexthop *b) {
	struct nexthop_info_srv6_local *ad, *bd;

	assert(a->type == GR_NH_T_SR6_LOCAL);
	assert(b->type == GR_NH_T_SR6_LOCAL);

	ad = nexthop_info_srv6_local(a);
	bd = nexthop_info_srv6_local(b);

	return ad->behavior == bd->behavior && ad->out_vrf_id == bd->out_vrf_id
		&& ad->flags == bd->flags;
}

static int srv6_local_nh_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_srv6_local *priv = nexthop_info_srv6_local(nh);
	const struct gr_nexthop_info_srv6_local *pub = info;

	priv->base = *pub;

	return 0;
}

static struct gr_nexthop *srv6_local_nh_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_srv6_local *sr6_priv = nexthop_info_srv6_local(nh);
	struct gr_nexthop_info_srv6_local *sr6_pub;
	struct gr_nexthop *pub;

	pub = malloc(sizeof(*pub) + sizeof(*sr6_pub));
	if (pub == NULL)
		return errno_set_null(ENOMEM);

	pub->base = nh->base;
	sr6_pub = (struct gr_nexthop_info_srv6_local *)pub->info;
	*sr6_pub = sr6_priv->base;

	*len = sizeof(*pub) + sizeof(*sr6_pub);

	return pub;
}

static struct nexthop_type_ops nh_ops = {
	.equal = srv6_local_nh_equal,
	.import_info = srv6_local_nh_import_info,
	.to_api = srv6_local_nh_to_api,
};

RTE_INIT(srv6_constructor) {
	nexthop_type_ops_register(GR_NH_T_SR6_LOCAL, &nh_ops);
}
