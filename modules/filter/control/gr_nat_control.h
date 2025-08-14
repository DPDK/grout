// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_nat.h>
#include <gr_net_types.h>

int snat44_static_policy_add(struct iface *, ip4_addr_t match, ip4_addr_t replace);
int snat44_static_policy_del(struct iface *, ip4_addr_t match);
bool snat44_static_lookup_translation(uint16_t iface_id, ip4_addr_t orig, ip4_addr_t *trans);

int snat44_dynamic_policy_add(const struct gr_snat44_policy *);
int snat44_dynamic_policy_del(const struct gr_snat44_policy *);
struct gr_snat44_policy *snat44_dynamic_policy_export(void);

struct nat44 {
	const struct gr_snat44_policy *policy;
	ip4_addr_t orig_addr;
	ip4_addr_t tran_addr;
	rte_be16_t orig_id;
	rte_be16_t tran_id;
};
