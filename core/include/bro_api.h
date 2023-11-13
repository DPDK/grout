// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BRO_API
#define _BRO_API

#include <stdint.h>

#define BRO_API_VERSION 1

struct bro_api_header {
	uint32_t version; // BRO_API_VERSION
	uint32_t status; // errno, only used for responses
	uint32_t type;
	uint32_t payload_len;
};

#define BRO_MAX_PAYLOAD_LEN (128 * 1024)
#define BRO_API_BUF_SIZE (sizeof(struct bro_api_header) + BRO_MAX_PAYLOAD_LEN)

#endif // _BRO_API
