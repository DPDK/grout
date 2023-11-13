// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BROUTER_CONTROL_PRIV
#define _BROUTER_CONTROL_PRIV

#include <bro_api.h>
#include <bro_control.h>

ctrl_handler_t *lookup_control_handler(uint32_t type);

#endif // _BROUTER_CONTROL_PRIV
