// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _IP4_MBUF_H
#define _IP4_MBUF_H

#include <br_mbuf.h>
#include <br_net_types.h>

BR_MBUF_PRIV_DATA_TYPE(ip_output_mbuf_data, { ip4_addr_t next_hop; });

#endif
