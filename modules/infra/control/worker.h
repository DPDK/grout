// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CONTROL_WORKER
#define _BR_CONTROL_WORKER

#include <br_port.h>
#include <br_worker.h>

int port_unplug(const struct port *, bool commit);
int port_plug(const struct port *, bool commit);
size_t worker_count(void);

#endif
