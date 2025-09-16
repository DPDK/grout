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

// Send a request and iterate over the received stream of responses.
//
// @p obj (const <any> *)
//     The iterating variable. It must be a (preferably const) pointer
//     to the type of objects returned by the requested API endpoint.
// @p ret (int)
//     The final return code of the operation.
// @p client <struct gr_api_client *>
//     Client object used to perform the requests.
// @p req_type <uint32_t>
//     Code for the request operation.
// @p tx_len <size_t>
//     Size of the request payload. Must be 0 if tx_data is NULL.
// @p tx_data <void *>
//     Request payload. Must be NULL if tx_len is 0.
//
// This should be used like a for loop, e.g.:
//
//     struct gr_ip4_route_list_req = {.vrf_id = 0};
//     const struct gr_ip4_route *r;
//     int ret;
//
//     gr_api_client_stream_foreach (r, ret, client, GR_IP4_ROUTE_LIST, sizeof(req), &req) {
//         do stuff with r;
//     }
//     if (ret < 0)
//         handle error;
//
// XXX: Interrupting the loop with break or an early return will cause memory leaks
// and will leave messages hanging in the socket buffer. Make sure to let the loop
// terminate gracefully.
#define gr_api_client_stream_foreach(obj, ret, client, req_type, tx_len, tx_data)                  \
	for (long int __id = gr_api_client_send(client, req_type, tx_len, tx_data), __first = 1;   \
	     ({                                                                                    \
		     if (__first == 1)                                                             \
			     ret = __id;                                                           \
		     __id >= 0 && __first; /* statement expression value */                        \
	     });                                                                                   \
	     __first = 0)                                                                          \
		for (void *__ptr = NULL; ({                                                        \
			     bool more = false;                                                    \
			     ret = gr_api_client_recv(client, __id, &__ptr);                       \
			     if (ret < 0) {                                                        \
				     free(__ptr);                                                  \
				     __ptr = NULL;                                                 \
			     } else if (__ptr != NULL) {                                           \
				     obj = __ptr;                                                  \
				     more = true;                                                  \
			     }                                                                     \
			     more; /* statement expression value */                                \
		     });                                                                           \
		     free(__ptr), __ptr = NULL)

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
