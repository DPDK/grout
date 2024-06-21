// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_CONTROL_WORKER
#define _GR_CONTROL_WORKER

#include "gr_worker.h"

int port_unplug(uint16_t port_id);
int port_plug(uint16_t port_id);

size_t worker_count(void);
int worker_create(unsigned cpu_id);
struct worker *worker_find(unsigned cpu_id);
int worker_destroy(unsigned cpu_id);
int worker_ensure_default(int socket_id);

#endif
