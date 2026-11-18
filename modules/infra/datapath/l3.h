// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include "mbuf.h"
#include "nexthop.h"

#include <rte_ip.h>
#include <rte_ip6.h>

GR_MBUF_PRIV_DATA_TYPE(l3_mbuf_data, { const struct nexthop *nh; });

#define GR_IP_IS_IPV4(ihl) (((ihl) >> 4) == IPVERSION)

static inline int gr_ip_l4_proto(const void *ip, size_t len, void **l4) {
	const struct rte_ipv4_hdr *ip4 = ip;
	const struct rte_ipv6_hdr *ip6;
	const uint8_t *end;
	const uint8_t *p;
	size_t ext_len;
	int proto;
	int next;

	if (len < sizeof(*ip4))
		return -1;

	if (GR_IP_IS_IPV4(ip4->version_ihl)) {
		if (l4)
			*l4 = (uint8_t *)ip + rte_ipv4_hdr_len(ip4);
		return ip4->next_proto_id;
	}

	ip6 = ip;
	if (len < sizeof(*ip6))
		return -1;

	proto = ip6->proto;
	p = (const uint8_t *)(ip6 + 1);
	end = (const uint8_t *)ip + len;

	while ((next = rte_ipv6_get_next_ext(p, proto, &ext_len)) >= 0 && ext_len > 0) {
		if (p + ext_len > end)
			return -1;
		p += ext_len;
		proto = next;
	}

	if (l4)
		*l4 = (void *)p;
	return proto;
}
