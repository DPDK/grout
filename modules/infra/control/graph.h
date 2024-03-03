// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_CONTROL_GRAPH
#define _BR_CONTROL_GRAPH

#include <br_worker.h>

int worker_graph_reload_all(void);
void worker_graph_free(struct worker *);

#endif
