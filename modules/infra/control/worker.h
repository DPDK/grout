// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CONTROL_WORKER
#define _BR_CONTROL_WORKER

#include <br_port.h>
#include <br_worker.h>

int port_unplug(const struct port *);
int port_plug(const struct port *);

size_t worker_count(void);
int worker_create(int cpu_id);
struct worker *worker_find(int cpu_id);
int worker_destroy(int cpu_id);
int worker_ensure_default(int socket_id);

#endif
