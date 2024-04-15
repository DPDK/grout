// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _IP4_MBUF_H
#define _IP4_MBUF_H

#include <br_mbuf.h>

BR_MBUF_PRIV_DATA_TYPE(ip_output_mbuf_data, { struct nexthop *nh; });

BR_MBUF_PRIV_DATA_TYPE(arp_mbuf_data, {
	struct nexthop *local;
	struct nexthop *remote;
});

#endif
