// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_worker.h>

int worker_graph_reload(struct worker *);
int worker_graph_reload_all(void);
void worker_graph_free(struct worker *);
