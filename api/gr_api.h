// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_API
#define _GR_API

#include <stddef.h>
#include <stdint.h>

#ifndef GROUT_VERSION
#define GROUT_VERSION "v0.1"
#endif

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

int gr_api_client_send_recv(
	const struct gr_api_client *,
	uint32_t req_type,
	size_t tx_len,
	const void *tx_data,
	void **rx_data
);

#define GR_MAIN_MODULE 0xcafe
#define GR_MAIN_EVENT_SUBSCRIBE REQUEST_TYPE(GR_MAIN_MODULE, 0xcafe)
struct gr_event_subscribe_req {
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

#endif
