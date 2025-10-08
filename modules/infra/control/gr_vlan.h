// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_iface.h>

#include <rte_ether.h>
#include <rte_mempool.h>

#include <stdint.h>
#include <sys/queue.h>

GR_IFACE_INFO(GR_IFACE_TYPE_VLAN, iface_info_vlan, { BASE(gr_iface_info_vlan); });

struct iface *vlan_get_iface(uint16_t port_id, uint16_t vlan_id);
