// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_CONTROL_GRAPH
#define _GR_CONTROL_GRAPH

#include <gr_worker.h>

int worker_graph_reload_all(void);
void worker_graph_free(struct worker *);

#endif
