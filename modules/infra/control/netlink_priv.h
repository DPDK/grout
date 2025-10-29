// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <stdbool.h>
#include <stdint.h>

int netlink_add_del_vrf_rules(const char *ifname, uint16_t vrf_id, bool add);
