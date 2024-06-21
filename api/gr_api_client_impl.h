// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

// This file must be included in *one* of your client application files.

#ifndef _GR_API_CLIENT_IMPL
#define _GR_API_CLIENT_IMPL

#include "gr_api.h"

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct gr_api_client {
	int sock_fd;
};

struct gr_api_client *gr_api_client_connect(const char *sock_path) {
	union {
		struct sockaddr_un un;
		struct sockaddr a;
	} addr;

	struct gr_api_client *client = calloc(1, sizeof(*client));
	if (client == NULL)
		goto err;

	client->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (client->sock_fd == -1)
		goto err;

	addr.un.sun_family = AF_UNIX;
	memccpy(addr.un.sun_path, sock_path, 0, sizeof(addr.un.sun_path) - 1);

	if (connect(client->sock_fd, &addr.a, sizeof(addr.un)) < 0)
		goto err;

	return client;

err:
	free(client);
	return NULL;
}

int gr_api_client_disconnect(struct gr_api_client *client) {
	if (client == NULL)
		return 0;
	int ret = close(client->sock_fd);
	free(client);
	return ret;
}

int gr_api_client_send_recv(
	const struct gr_api_client *client,
	uint32_t req_type,
	size_t tx_len,
	const void *tx_data,
	void **rx_data
) {
	struct gr_api_request *req = NULL;
	struct gr_api_response resp;
	static uint32_t message_id;
	uint32_t id = ++message_id;
	void *payload = NULL;
	ssize_t n;

	if (client == NULL) {
		errno = EINVAL;
		goto err;
	}
	if ((req = malloc(sizeof(*req) + tx_len)) == NULL)
		goto err;

	req->id = id;
	req->type = req_type;
	req->payload_len = tx_len;
	if (tx_len > 0)
		memcpy(PAYLOAD(req), tx_data, tx_len);

	if (send(client->sock_fd, req, sizeof(*req) + tx_len, 0) < 0)
		goto err;

	if ((n = recv(client->sock_fd, &resp, sizeof(resp), 0)) < 0)
		goto err;

	if (n != sizeof(resp) || resp.for_id != id) {
		errno = EBADMSG;
		goto err;
	}
	if (resp.payload_len > 0) {
		// receive payload *before* checking response status to drain socket buffer
		if ((payload = malloc(resp.payload_len)) == NULL)
			goto err;
		if ((n = recv(client->sock_fd, payload, resp.payload_len, 0)) < 0)
			goto err;
	}
	if (resp.status != 0) {
		errno = resp.status;
		goto err;
	}

	if (payload != NULL && rx_data != NULL)
		*rx_data = payload;

	free(req);
	return 0;
err:
	free(req);
	free(payload);
	return -1;
}

#endif
