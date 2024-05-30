// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _IPIP_PRIV_H
#define _IPIP_PRIV_H

#include <br_iface.h>
#include <br_net_types.h>

#include <stdint.h>

struct iface_info_ipip {
	ip4_addr_t local;
	ip4_addr_t remote;
};

struct iface *ipip_get_iface(ip4_addr_t local, ip4_addr_t remote, uint16_t vrf_id);

#endif
