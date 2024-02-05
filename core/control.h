// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CONTROL_PRIV
#define _BR_CONTROL_PRIV

#include <br_api.h>
#include <br_control.h>

const struct br_api_handler *lookup_api_handler(const struct br_api_request *);

void modules_init(void);

void modules_fini(void);

#endif
