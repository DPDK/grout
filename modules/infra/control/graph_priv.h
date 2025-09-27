// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_port.h>
#include <gr_vec.h>
#include <gr_worker.h>

int worker_graph_reload(struct worker *, gr_vec struct iface_info_port **);
int worker_graph_reload_all(gr_vec struct iface_info_port **);
void worker_graph_free(struct worker *);
