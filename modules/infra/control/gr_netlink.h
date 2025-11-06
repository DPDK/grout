// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <stdbool.h>

int netlink_link_set_admin_state(const char *ifname, bool up);
int netlink_link_set_master(const char *ifname, const char *master_ifname);
int netlink_link_add_vrf(const char *vrf_name, uint32_t table_id);
int netlink_link_del_iface(const char *ifname);
int netlink_add_route(const char *ifname, uint32_t table);
int netlink_del_route(const char *ifname, uint32_t table);
