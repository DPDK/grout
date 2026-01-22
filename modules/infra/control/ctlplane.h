// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#pragma once

#include <gr_control_queue.h>
#include <gr_infra.h>

void iface_cp_tx(void *obj, uintptr_t priv, const struct control_queue_drain *);
