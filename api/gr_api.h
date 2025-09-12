// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct gr_api_request {
	uint32_t id;
	uint32_t type;
	uint32_t payload_len;
};

struct gr_api_response {
	uint32_t for_id; // matches gr_api_request.id
	uint32_t status; // uses errno values
	uint32_t payload_len;
};

#define GR_API_MAX_MSG_LEN (128 * 1024)

#define REQUEST_TYPE(module, id) (((uint32_t)(0xffff & module) << 16) | (0xffff & id))
#define EVENT_TYPE(module, id) (((uint32_t)(0xffff & module) << 16) | (0xffff & id))
#define EVENT_TYPE_ALL UINT32_C(0xffffffff)

#define GR_DEFAULT_SOCK_PATH "/run/grout.sock"

struct gr_api_client;

struct gr_api_client *gr_api_client_connect(const char *sock_path);

int gr_api_client_disconnect(struct gr_api_client *);

long int
gr_api_client_send(struct gr_api_client *, uint32_t req_type, size_t tx_len, const void *tx_data);

int gr_api_client_recv(struct gr_api_client *, uint32_t for_id, void **rx_data);

static inline int gr_api_client_send_recv(
	struct gr_api_client *client,
	uint32_t req_type,
	size_t tx_len,
	const void *tx_data,
	void **rx_data
) {
	long int ret = gr_api_client_send(client, req_type, tx_len, tx_data);
	if (ret < 0)
		return ret;
	return gr_api_client_recv(client, ret, rx_data);
}

#define GR_MAIN_MODULE 0xcafe

#define GR_MAIN_HELLO REQUEST_TYPE(GR_MAIN_MODULE, 0x1981)
struct gr_hello_req {
	char version[128];
};
// struct gr_hello_resp { };

#define GR_MAIN_EVENT_SUBSCRIBE REQUEST_TYPE(GR_MAIN_MODULE, 0xcafe)
struct gr_event_subscribe_req {
	// If true, suppress events originating from API messages made by the same PID as the
	// subscriber socket.
	bool suppress_self_events;
	uint32_t ev_type;
};
// struct gr_event_subscribe_resp { };
#define GR_MAIN_EVENT_UNSUBSCRIBE REQUEST_TYPE(GR_MAIN_MODULE, 0xcaff)
// struct gr_event_unsubscribe_req { };
// struct gr_event_unsubscribe_resp { };

struct gr_api_event {
	uint32_t ev_type;
	size_t payload_len;
};

int gr_api_client_event_recv(const struct gr_api_client *, struct gr_api_event **);
