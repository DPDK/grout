// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_net_types.h>

int snat44_static_policy_add(struct iface *, ip4_addr_t match, ip4_addr_t replace);
int snat44_static_policy_del(struct iface *, ip4_addr_t match);
bool snat44_static_lookup_translation(uint16_t iface_id, ip4_addr_t orig, ip4_addr_t *trans);
