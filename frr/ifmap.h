// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Christophe Fontaine, Red Hat

#pragma once

#include <lib/if.h>
#include <lib/memory.h>
#include <lib/vrf.h>

DECLARE_MGROUP(GROUT);
DECLARE_MTYPE(GROUT_MEM);

bool zg_ifmap_add(uint16_t grout_ifindex, ifindex_t frr_ifindex);
bool zg_ifmap_del(uint16_t grout_ifindex);

ifindex_t zg_ifindex_to_frr(uint16_t grout_ifindex);
uint16_t zg_ifindex_to_grout(ifindex_t frr_ifindex);

vrf_id_t zg_vrf_to_frr(uint16_t gr_vrf_id);
uint16_t zg_vrf_to_grout(vrf_id_t frr_vrf_id);

void zg_ifmap_init(void);
