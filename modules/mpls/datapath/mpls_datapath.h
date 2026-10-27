// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#pragma once

#include "mbuf.h"
#include "nexthop.h"

#include <rte_byteorder.h>
#include <rte_mpls.h>

static inline uint32_t mpls_hdr_get_label(const struct rte_mpls_hdr *h) {
	return (rte_be_to_cpu_16(h->tag_msb) << 4) | h->tag_lsb;
}

static inline void mpls_hdr_set_label(struct rte_mpls_hdr *h, uint32_t label) {
	h->tag_msb = rte_cpu_to_be_16(label >> 4);
	h->tag_lsb = label & 0xf;
}

GR_MBUF_PRIV_DATA_TYPE(mpls_hold_mbuf_data, {
	const struct nexthop *nh;
	const struct nexthop *mpls_nh;
});

int mpls_resubmit_cb(struct rte_mbuf *, struct nexthop *);
