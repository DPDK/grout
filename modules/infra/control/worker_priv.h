// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <gr_port.h>
#include <gr_worker.h>

int port_unplug(struct iface_info_port *);
int port_plug(struct iface_info_port *);
int port_configure(struct iface_info_port *, uint16_t n_txq_min);

unsigned worker_count(void);
int worker_create(unsigned cpu_id);
struct worker *worker_find(unsigned cpu_id);
int worker_destroy(unsigned cpu_id);
