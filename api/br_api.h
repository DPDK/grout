// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_API
#define _BR_API

#include <stddef.h>
#include <stdint.h>

struct br_api_request {
	uint32_t id;
	uint32_t type;
	uint32_t payload_len;
};

struct br_api_response {
	uint32_t for_id; // matches br_api_request.id
	uint32_t status; // uses errno values
	uint32_t payload_len;
};

#define BR_API_MAX_MSG_LEN (128 * 1024)

#define REQUEST_TYPE(module, id) (((uint32_t)(0xffff & module) << 16) | (0xffff & id))
#define PAYLOAD(header) ((void *)(header + 1))

#define BR_DEFAULT_SOCK_PATH "/run/br.sock"

struct br_api_client;

struct br_api_client *br_api_client_connect(const char *sock_path);

int br_api_client_disconnect(struct br_api_client *);

int br_api_client_send_recv(
	const struct br_api_client *,
	uint32_t req_type,
	size_t tx_len,
	const void *tx_data,
	void **rx_data
);

#endif
