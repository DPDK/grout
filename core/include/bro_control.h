// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BROUTER_CONTROL
#define _BROUTER_CONTROL

#include "bro_api.h"

#include <stdint.h>

typedef uint16_t(ctrl_handler_t)(struct bro_api_header *, void *payload);

void bro_register_handler(uint32_t type, ctrl_handler_t *callback);

#endif // _BROUTER_CONTROL
