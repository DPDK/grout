// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#pragma once

#include <rte_common.h>
#include <rte_graph.h>
#include <rte_mbuf.h>

rte_edge_t gr_control_input_register_handler(const char *node_name);

__rte_warn_unused_result int post_to_stack(rte_edge_t edge, struct rte_mbuf *m);

// True if the control input ring has packets waiting to be drained by a worker.
bool control_input_pending(void);
