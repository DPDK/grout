// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#pragma once

#include <gr_ip6_control.h>
#include <gr_nh_control.h>
#include <gr_srv6.h>

//
// srv6 local data stored in nexthop priv
//
GR_NH_TYPE_INFO(GR_NH_T_SR6_LOCAL, nexthop_info_srv6_local, { BASE(gr_nexthop_info_srv6_local); });

//
// srv6 encap data is allocated dynamically.
// A pointer to it is stored in nexthop priv.
//
GR_NH_TYPE_INFO(GR_NH_T_SR6_OUTPUT, nexthop_info_srv6_output, {
	gr_srv6_encap_behavior_t encap;
	uint16_t n_seglist;
	struct rte_ipv6_addr *seglist;
});

extern struct nexthop *tunsrc_nh;
static inline const struct nexthop *
sr_tunsrc_get(uint16_t iface_id, const struct rte_ipv6_addr *dst) {
	return tunsrc_nh ? tunsrc_nh : addr6_get_preferred(iface_id, dst);
}
