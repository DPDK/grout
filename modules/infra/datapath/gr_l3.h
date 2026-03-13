// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_mbuf.h>
#include <gr_nh_control.h>

GR_MBUF_PRIV_DATA_TYPE(l3_mbuf_data, { const struct nexthop *nh; });
