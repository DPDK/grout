// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CONTROL
#define _BR_CONTROL

#include <br_api.h>

#include <stdint.h>

typedef void(br_api_handler_t)(void *req_payload, struct br_api_response *);

void br_register_api_handler(uint32_t request_type, br_api_handler_t *);

#endif
