// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Christophe Fontaine, Red Hat

#pragma once

#include <lib/if.h>
#include <lib/memory.h>

DECLARE_MGROUP(GROUT);
DECLARE_MTYPE(GROUT_MEM);

bool add_ifindex_mapping(ifindex_t grout_ifindex, ifindex_t frr_ifindex);
bool remove_mapping_by_grout_ifindex(ifindex_t grout_ifindex);

ifindex_t ifindex_grout_to_frr(int16_t grout_ifindex);
uint16_t ifindex_frr_to_grout(ifindex_t frr_ifindex);
void init_ifindex_mappings(void);
