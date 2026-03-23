// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

// This file must be included in *one* of your client application files.

#pragma once

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

#ifdef GR_REQ
#error "gr_api_client_impl.h must be included *first*, before any other gr_*.h headers"
#endif

struct api_message {
	uint32_t type;
	const char *name;
	size_t payload_min_size;
	bool stream;
	STAILQ_ENTRY(api_message) next;
};

static STAILQ_HEAD(, api_message) messages = STAILQ_HEAD_INITIALIZER(messages);

static const struct api_message *get_message(uint32_t type) {
	struct api_message *m;

	STAILQ_FOREACH (m, &messages, next) {
		if (m->type == type)
			return m;
	}

	errno = EIDRM;
	return NULL;
}

static void register_message(struct api_message *m) {
	const struct api_message *existing = get_message(m->type);

	if (existing != NULL) {
		fprintf(stderr,
			"fatal: message %s has duplicate type id %#08x with message %s",
			m->name,
			m->type,
			existing->name);
		abort();
	}
	STAILQ_INSERT_TAIL(&messages, m, next);
}

#define GR_REQ(r, req, resp)                                                                       \
	static struct api_message r##_msg = {                                                      \
		.type = r,                                                                         \
		.name = #r,                                                                        \
		.payload_min_size = sizeof(resp),                                                  \
	};                                                                                         \
	static void __attribute__((constructor, used)) r##_init(void) {                            \
		register_message(&r##_msg);                                                        \
	}

#define GR_REQ_STREAM(r, req, resp)                                                                \
	static struct api_message r##_msg = {                                                      \
		.type = r,                                                                         \
		.name = #r,                                                                        \
		.payload_min_size = sizeof(resp),                                                  \
		.stream = true,                                                                    \
	};                                                                                         \
	static void __attribute__((constructor, used)) r##_init(void) {                            \
		register_message(&r##_msg);                                                        \
	}

#define GR_EVENT(e, obj) GR_REQ(e, , obj)

#include <grout.h>

#include <assert.h>
#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

const char *gr_api_message_name(uint32_t type) {
	static __thread char buf[64];
	const struct api_message *m = get_message(type);
	if (m == NULL) {
		snprintf(buf, sizeof(buf), "0x%08x?", type);
		return buf;
	}
	return m->name;
}

struct response {
	struct gr_api_response header;
	void *payload;
	int fd; // received via SCM_RIGHTS, -1 if none
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
	if (memccpy(addr.un.sun_path, sock_path, 0, sizeof(addr.un.sun_path)) == NULL) {
		errno = ENAMETOOLONG;
		goto err;
	}

	if (connect(client->sock_fd, &addr.a, sizeof(addr.un)) < 0)
		goto err;

	struct gr_hello_req hello = {.api_version = GR_API_VERSION, .version = GROUT_VERSION};
	if (gr_api_client_send_recv(client, GR_HELLO, sizeof(hello), &hello, NULL) < 0)
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
		if (resp->fd >= 0)
			close(resp->fd);
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
		if (n < 0)
			return n;

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
		n = recv(c->sock_fd, ptr, remaining, 0);
		if (n == 0) {
			errno = ECONNRESET;
			return len - remaining;
		} else if (n < 0) {
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

// Receive a response header, potentially with an SCM_RIGHTS fd.
// Uses recvmsg() so ancillary data is captured.
static int
recv_response_header(const struct gr_api_client *c, struct gr_api_response *resp, int *recv_fd) {
	*recv_fd = -1;

	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} cmsg_buf;
	memset(&cmsg_buf, 0, sizeof(cmsg_buf));

	struct iovec iov = {.iov_base = resp, .iov_len = sizeof(*resp)};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsg_buf.buf,
		.msg_controllen = sizeof(cmsg_buf.buf),
	};

	ssize_t n = recvmsg(c->sock_fd, &msg, MSG_CMSG_CLOEXEC);

	if (n == 0) {
		errno = ECONNRESET;
		return -1;
	}
	if (n < 0)
		return -1;
	if ((size_t)n < sizeof(*resp)) {
		errno = EPROTO;
		return -1;
	}

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg != NULL && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
		memcpy(recv_fd, CMSG_DATA(cmsg), sizeof(int));

	return 0;
}

int gr_api_client_recv_fd(
	struct gr_api_client *client,
	uint32_t req_type,
	uint32_t for_id,
	void **rx_data,
	int *fd
) {
	struct response *cached = NULL;
	const struct api_message *m;
	struct gr_api_response resp;
	void *payload = NULL;
	int recv_fd = -1;

	if (fd != NULL)
		*fd = -1;

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
		recv_fd = cached->fd;
		free(cached);
		goto out;
	}
recv:
	// No matching cached message, try to receive one from the socket.
	if (recv_response_header(client, &resp, &recv_fd) < 0)
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
		cached->fd = recv_fd;
		STAILQ_INSERT_TAIL(&client->responses, cached, next);
		payload = NULL;
		recv_fd = -1;
		// And try to receive the next message until we get the correct ID.
		goto recv;
	}
out:
	if (resp.status != 0) {
		errno = resp.status;
		goto err;
	}

	m = get_message(req_type);
	if (m == NULL) {
		goto err;
	}

	if (resp.payload_len < m->payload_min_size && (!m->stream || resp.payload_len != 0)) {
		errno = EMSGSIZE;
		goto err;
	}
	if (payload != NULL) {
		assert(rx_data != NULL);
		*rx_data = payload;
	}
	if (fd != NULL)
		*fd = recv_fd;
	else if (recv_fd >= 0)
		close(recv_fd);

	return 0;
err:
	if (recv_fd >= 0)
		close(recv_fd);
	free(payload);
	return -errno;
}

int gr_api_client_recv(
	struct gr_api_client *client,
	uint32_t req_type,
	uint32_t for_id,
	void **rx_data
) {
	return gr_api_client_recv_fd(client, req_type, for_id, rx_data, NULL);
}

int gr_api_client_event_recv(const struct gr_api_client *c, struct gr_api_event **event) {
	const struct api_message *m;
	struct gr_api_event header;

	*event = NULL;
	if (recv_all(c, &header, sizeof(header)) != sizeof(header))
		goto err;

	if (header.payload_len > GR_API_MAX_MSG_LEN) {
		errno = EMSGSIZE;
		goto err;
	}
	m = get_message(header.ev_type);
	if (m == NULL) {
		goto err;
	}
	if (header.payload_len < m->payload_min_size) {
		errno = EMSGSIZE;
		goto err;
	}
	if (header.payload_len > 0) {
		if ((*event = malloc(sizeof(header) + header.payload_len)) == NULL)
			goto err;
		**event = header;
		if (recv_all(c, PAYLOAD(*event), header.payload_len) != (int)header.payload_len)
			goto err;
	}
	return 0;

err:
	free(*event);
	*event = NULL;
	return -errno;
}

// Drain remaining responses from a stream request until the terminator arrives.
int __gr_api_client_stream_drain(struct gr_api_client *c, uint32_t req_type, uint32_t for_id) {
	void *ptr;
	int ret;

	do {
		ptr = NULL;
		ret = gr_api_client_recv(c, req_type, for_id, &ptr);
		free(ptr);
	} while (ptr != NULL);

	return ret;
}
