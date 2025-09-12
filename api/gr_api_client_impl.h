// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

// This file must be included in *one* of your client application files.

#pragma once

#include <gr_api.h>
#include <gr_errno.h>
#include <gr_macro.h>
#include <gr_version.h>

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct response {
	struct gr_api_response header;
	void *payload;
	STAILQ_ENTRY(response) next;
};

struct gr_api_client {
	int sock_fd;
	STAILQ_HEAD(, response) responses;
};

struct gr_api_client *gr_api_client_connect(const char *sock_path) {
	union {
		struct sockaddr_un un;
		struct sockaddr a;
	} addr;

	struct gr_api_client *client = calloc(1, sizeof(*client));
	if (client == NULL)
		goto err;

	STAILQ_INIT(&client->responses);
	client->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (client->sock_fd == -1)
		goto err;

	addr.un.sun_family = AF_UNIX;
	memccpy(addr.un.sun_path, sock_path, 0, sizeof(addr.un.sun_path) - 1);

	if (connect(client->sock_fd, &addr.a, sizeof(addr.un)) < 0)
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
	while (!STAILQ_EMPTY(&client->responses)) {
		struct response *resp = STAILQ_FIRST(&client->responses);
		STAILQ_REMOVE_HEAD(&client->responses, next);
		free(resp->payload);
		free(resp);
	}
	free(client);
	return ret;
}

static ssize_t send_all(const struct gr_api_client *c, const void *buf, size_t len) {
	size_t remaining = len;
	const char *ptr = buf;
	ssize_t n;

	while (remaining > 0) {
		n = send(c->sock_fd, ptr, remaining, MSG_NOSIGNAL);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return n;
		}

		ptr += n;
		remaining -= n;
	}

	return len;
}

static ssize_t recv_all(const struct gr_api_client *c, void *buf, size_t len) {
	size_t remaining = len;
	char *ptr = buf;
	ssize_t n;

	while (remaining > 0) {
		n = recv(c->sock_fd, ptr, remaining, MSG_WAITALL);
		if (n == 0) {
			errno = ECONNRESET;
			return len - remaining;
		} else if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return n;
		}

		ptr += n;
		remaining -= n;
	}

	return len;
}

long int gr_api_client_send(
	struct gr_api_client *client,
	uint32_t req_type,
	size_t tx_len,
	const void *tx_data
) {
	static uint32_t message_id;

	if (client == NULL || (tx_len == 0 && tx_data != NULL) || (tx_len > 0 && tx_data == NULL))
		return errno_set(EINVAL);

	struct gr_api_request req = {
		.id = ++message_id,
		.payload_len = tx_len,
		.type = req_type,
	};

	if (send_all(client, &req, sizeof(req)) < 0)
		return -errno;

	if (tx_len > 0 && send_all(client, tx_data, tx_len) < 0)
		return -errno;

	return req.id;
}

int gr_api_client_recv(struct gr_api_client *client, uint32_t for_id, void **rx_data) {
	struct response *cached = NULL;
	struct gr_api_response resp;
	void *payload = NULL;

	if (client == NULL)
		return errno_set(EINVAL);

	// Before receiving from the socket,
	// check if there are any cached messages with the requested ID.
	STAILQ_FOREACH (cached, &client->responses, next) {
		if (cached->header.for_id == for_id)
			break;
	}
	if (cached != NULL) {
		// Remove the cached message from the list and return it.
		STAILQ_REMOVE(&client->responses, cached, response, next);
		resp = cached->header;
		payload = cached->payload;
		free(cached);
		goto out;
	}
recv:
	// No matching cached message, try to receive one from the socket.
	if (recv_all(client, &resp, sizeof(resp)) != sizeof(resp))
		goto err;

	if (resp.payload_len > GR_API_MAX_MSG_LEN) {
		errno = EMSGSIZE;
		goto err;
	}
	if (resp.payload_len > 0) {
		// receive payload *before* checking response status to drain socket buffer
		if ((payload = malloc(resp.payload_len)) == NULL)
			goto err;
		if (recv_all(client, payload, resp.payload_len) != resp.payload_len)
			goto err;
	}
	if (resp.for_id != for_id) {
		// Not the message ID we expected. Enqueue it to the cached messages.
		cached = malloc(sizeof(*cached));
		if (cached == NULL)
			goto err;
		cached->header = resp;
		cached->payload = payload;
		STAILQ_INSERT_TAIL(&client->responses, cached, next);
		payload = NULL;
		// And try to receive the next message until we get the correct ID.
		goto recv;
	}
out:
	if (resp.status != 0) {
		errno = resp.status;
		goto err;
	}
	if (payload != NULL) {
		assert(rx_data != NULL);
		*rx_data = payload;
	}

	return 0;
err:
	free(payload);
	return -errno;
}

int gr_api_client_event_recv(const struct gr_api_client *c, struct gr_api_event **event) {
	struct gr_api_event header;

	*event = NULL;
	if (recv_all(c, &header, sizeof(header)) != sizeof(header))
		goto err;

	if (header.payload_len > GR_API_MAX_MSG_LEN) {
		errno = EMSGSIZE;
		goto err;
	}
	if (header.payload_len > 0) {
		if ((*event = malloc(sizeof(header) + header.payload_len)) == NULL)
			goto err;
		(*event)->ev_type = header.ev_type;
		(*event)->payload_len = header.payload_len;
		if (recv_all(c, PAYLOAD(*event), header.payload_len) != (int)header.payload_len)
			goto err;
	}
	return 0;

err:
	free(*event);
	*event = NULL;
	return -errno;
}
