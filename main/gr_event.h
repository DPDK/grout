// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#ifndef _GR_EVENT
#define _GR_EVENT

#include <stddef.h>
#include <stdint.h>

void gr_event_push(uint32_t ev_type, size_t len, const void *data);

#endif
