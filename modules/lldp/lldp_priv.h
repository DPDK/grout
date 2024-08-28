// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#ifndef _LLDP_PRIV_H
#define _LLDP_PRIV_H

#include <gr_iface.h>

#include <rte_ether.h>

#include <stdint.h>

struct lldp_ip4 {
	uint8_t afi;
	rte_be32_t ip4_addr;
} __rte_packed;

struct lldp_ip6 {
	uint8_t afi;
	uint8_t ip6_addr[16];
} __rte_packed;

int lldp_output_emit(const struct iface *);

#endif
