// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_iface.h>

#include <rte_ether.h>

int port_mac_add(struct iface *, const struct rte_ether_addr *);
int port_mac_del(struct iface *, const struct rte_ether_addr *);
int port_promisc_set(struct iface *, bool enabled);
int port_allmulti_set(struct iface *, bool enabled);
