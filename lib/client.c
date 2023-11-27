// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include <br_api.h>
#include <br_client.h>
#include <br_client_priv.h>

#include <errno.h>
#include <getopt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct br_client *br_connect(const char *sock_path) {
	struct sockaddr_un addr = {.sun_family = AF_UNIX};

	struct br_client *client = calloc(1, sizeof(*client));
	if (client == NULL)
		goto err;

	client->sock_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (client->sock_fd == -1)
		goto err;

	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

	if (connect(client->sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto err;

	return client;

err:
	free(client);
	return NULL;
}

int br_disconnect(struct br_client *client) {
	if (client == NULL)
		return 0;
	int ret = close(client->sock_fd);
	free(client);
	return ret;
}

int send_recv(
	const struct br_client *client,
	uint32_t req_type,
	size_t tx_len,
	const void *tx_data,
	size_t rx_len,
	void *rx_data
) {
	uint8_t buf[BR_API_MAX_MSG_LEN];
	struct br_api_request *req = (void *)buf;
	struct br_api_response *resp = (void *)buf;
	static uint32_t message_id;
	uint32_t id = ++message_id;
	ssize_t n;

	if (client == NULL) {
		errno = EINVAL;
		return -1;
	}

	req->id = id;
	req->type = req_type;
	req->payload_len = tx_len;
	if (tx_len > 0)
		memcpy(PAYLOAD(req), tx_data, tx_len);

	if (send(client->sock_fd, req, sizeof(*req) + tx_len, 0) < 0)
		return -1;

	if ((n = recv(client->sock_fd, resp, sizeof(buf), 0)) < 0)
		return -1;

	if (n < (ssize_t)sizeof(*resp)) {
		errno = EBADMSG;
		return -1;
	}
	if (resp->for_id != id) {
		errno = EBADMSG;
		return -1;
	}
	if (resp->status != 0) {
		errno = resp->status;
		return -1;
	}
	if ((size_t)n != sizeof(*resp) + rx_len) {
		errno = EBADMSG;
		return -1;
	}
	if (resp->payload_len != rx_len) {
		errno = EBADMSG;
		return -1;
	}
	if (rx_len > 0)
		memcpy(rx_data, PAYLOAD(resp), rx_len);

	return 0;
}
