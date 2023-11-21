// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_API
#define _BR_API

#include <br_api.pb-c.h>

#include <stddef.h>
#include <stdint.h>

#define BR_MAX_MSG_LEN (128 * 1024)
#define BR_PROTO_ALLOCATOR NULL

// build a new api request
// takes ownership of payload
Br__Request *
br_new_request(uint64_t id, uint16_t service, uint16_t method, size_t len, uint8_t *payload);

// build a new api response
// takes ownership of payload
Br__Response *br_new_response(const Br__Request *, uint32_t status, size_t len, uint8_t *payload);

static inline uint32_t br_service_method(uint16_t service, uint16_t method) {
	return (uint32_t)service << 16 | method;
}

static inline uint16_t br_service_id(uint32_t service_method) {
	return service_method >> 16;
}

static inline uint16_t br_medhot_id(uint32_t service_method) {
	return 0xffff & service_method;
}

#endif
