// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_net_types.h>

#include <stdbool.h>

int netlink_link_set_admin_state(uint32_t ifindex, bool up);
int netlink_link_set_master(uint32_t ifindex, uint32_t master_ifindex);
int netlink_link_set_name(uint32_t ifindex, const char *ifname);
int netlink_link_add_vrf(const char *vrf_name, uint32_t table_id);
int netlink_link_del_iface(uint32_t ifindex);
int netlink_add_route(uint32_t ifindex, uint32_t table);
int netlink_del_route(uint32_t ifindex, uint32_t table);
int netlink_add_addr4(uint32_t ifindex, ip4_addr_t ip);
int netlink_del_addr4(uint32_t ifindex, ip4_addr_t ip);
int netlink_add_addr6(uint32_t ifindex, const struct rte_ipv6_addr *ip);
int netlink_del_addr6(uint32_t ifindex, const struct rte_ipv6_addr *ip);
int netlink_set_addr_gen_mode_none(uint32_t ifindex);
int netlink_set_ifalias(uint32_t ifindex, const char *ifalias);
