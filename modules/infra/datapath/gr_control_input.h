// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#ifndef _GR_CONTROL_INPUT_PATH
#define _GR_CONTROL_INPUT_PATH

#include "gr_mbuf.h"

#include <rte_graph.h>

typedef enum {
	CONTROL_INPUT_UNKNOWN = 0,
	CONTROL_INPUT_ARP_REQUEST
} control_input_t;

GR_MBUF_PRIV_DATA_TYPE(control_input_mbuf_data, { void *data; });

void gr_control_input_add_handler(control_input_t type, const char *node_name);
int post_to_stack(control_input_t type, void *data);

#endif
