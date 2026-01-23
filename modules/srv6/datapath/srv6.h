// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#pragma once

#include <gr_mbuf.h>
#include <gr_nexthop.h>

GR_MBUF_PRIV_DATA_TYPE(srv6_dx2_mbuf_data, { struct nexthop *nh; })
