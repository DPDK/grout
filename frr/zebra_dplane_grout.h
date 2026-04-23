// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_net_types.h>

#include <lib/ipaddr.h>
#include <lib/ns.h>
#include <stddef.h>
#include <stdint.h>

#define GROUT_NS NS_DEFAULT

int grout_client_send_recv(uint32_t req_type, size_t tx_len, const void *tx_data, void **rx_data);

void ipaddr_to_l3_addr(struct l3_addr *dst, const struct ipaddr *src);

void l3_addr_to_ipaddr(struct ipaddr *dst, const struct l3_addr *src);
