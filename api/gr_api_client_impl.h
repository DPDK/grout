// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

// This file must be included in *one* of your client application files.

#ifndef _GR_API_CLIENT_IMPL
#define _GR_API_CLIENT_IMPL

#include <gr_api.h>
#include <gr_macro.h>
#include <gr_version.h>

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

struct gr_api_client *gr_api_client_connect(const char *sock_name) {
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
	addr.un.sun_path[0] = '\0';
	memccpy(addr.un.sun_path + 1, sock_name, 0, sizeof(addr.un.sun_path) - 2);

	if (connect(client->sock_fd,
		    &addr.a,
		    offsetof(struct sockaddr_un, sun_path) + strlen(sock_name) + 1)
	    < 0)
		goto err;

	struct gr_hello_req hello = {.version = GROUT_VERSION};
	if (gr_api_client_send_recv(client, GR_MAIN_HELLO, sizeof(hello), &hello, NULL) < 0)
		goto err;

	return client;

err:
	int errsave = errno;
	gr_api_client_disconnect(client);
	errno = errsave;
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
	if (resp.payload_len > GR_API_MAX_MSG_LEN) {
		errno = EMSGSIZE;
		goto err;
	}
	if (resp.payload_len > 0) {
		// receive payload *before* checking response status to drain socket buffer
		if ((payload = malloc(resp.payload_len)) == NULL)
			goto err;
		if (recv(client->sock_fd, payload, resp.payload_len, 0) < 0)
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
	return -errno;
}

int gr_api_client_event_recv(const struct gr_api_client *c, struct gr_api_event **event) {
	struct gr_api_event header;
	ssize_t n;

	*event = NULL;
	if ((n = recv(c->sock_fd, &header, sizeof(header), 0)) < 0) {
		goto err;
	}

	if (n != sizeof(header)) {
		errno = EBADMSG;
		goto err;
	}
	if (header.payload_len > GR_API_MAX_MSG_LEN) {
		errno = EMSGSIZE;
		goto err;
	}
	if (header.payload_len > 0) {
		if ((*event = malloc(sizeof(header) + header.payload_len)) == NULL)
			goto err;
		(*event)->ev_type = header.ev_type;
		(*event)->payload_len = header.payload_len;
		if (recv(c->sock_fd, PAYLOAD(*event), header.payload_len, 0) < 0)
			goto err;
	}
	return 0;

err:
	free(*event);
	*event = NULL;
	return -errno;
}

#endif
