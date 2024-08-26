// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP6_DATAPATH_H
#define _GR_IP6_DATAPATH_H

#include <gr_icmp6.h>
#include <gr_iface.h>
#include <gr_ip6_control.h>
#include <gr_mbuf.h>
#include <gr_net_types.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip6.h>

#include <stdint.h>

GR_MBUF_PRIV_DATA_TYPE(ip6_output_mbuf_data, { struct nexthop6 *nh; });

#endif
