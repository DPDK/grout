// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy

#pragma once

#include <gr_nh_control.h>

//
// vrf route data stored in nexthop priv
//
GR_NH_PRIV_DATA_TYPE(vrf_route_nh_priv, { uint16_t out_vrf_id; });
