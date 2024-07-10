// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#ifndef _GR_CONTROL_INPUT_PATH
#define _GR_CONTROL_INPUT_PATH

#include "gr_mbuf.h"

#include <rte_graph.h>

GR_MBUF_PRIV_DATA_TYPE(control_input_mbuf_data, { void *data; });

typedef uint8_t control_input_t;

control_input_t gr_control_input_register_handler(const char *node_name);
int post_to_stack(control_input_t type, void *data);

#endif
