// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#pragma once

#include <gr_control_input.h>

#include <rte_byteorder.h>

void loopback_tx(struct rte_mbuf *m);
control_input_t loopback_get_control_id(void);
