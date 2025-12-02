// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#pragma once

#include <gr_control_output.h>
#include <gr_infra.h>

void iface_cp_tx(struct rte_mbuf *m, const struct control_output_drain *);
