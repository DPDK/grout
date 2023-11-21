// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CONTROL
#define _BR_CONTROL

#include <br_api.pb-c.h>

#include <stdint.h>

typedef Br__Response *(br_service_handler_t)(const Br__Request *);

void br_register_service_handler(uint16_t type, br_service_handler_t *callback);

#endif
