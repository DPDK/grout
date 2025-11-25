// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <gr_net_types.h>

#include <rte_ether.h>

#include <stdbool.h>

int netlink_link_set_admin_state(const char *ifname, bool up);
int netlink_link_set_master(const char *ifname, const char *master_ifname);
int netlink_link_add_vrf(const char *vrf_name, uint32_t table_id);
int netlink_link_del_iface(const char *ifname);
int netlink_add_route(const char *ifname, uint32_t table);
int netlink_del_route(const char *ifname, uint32_t table);
int netlink_add_addr4(const char *ifname, ip4_addr_t ip);
int netlink_del_addr4(const char *ifname, ip4_addr_t ip);
int netlink_add_addr6(const char *ifname, const struct rte_ipv6_addr *ip);
int netlink_del_addr6(const char *ifname, const struct rte_ipv6_addr *ip);
int netlink_set_addr_gen_mode_none(const char *ifname);
int netlink_set_ifalias(const char *ifname, const char *ifalias);
int netlink_link_set_mtu(const char *ifname, uint32_t mtu);
int netlink_link_set_hwaddr(const char *ifname, const struct rte_ether_addr *addr);
int netlink_link_get_mtu(const char *ifname, uint32_t *mtu);
int netlink_link_get_hwaddr(const char *ifname, struct rte_ether_addr *addr);
