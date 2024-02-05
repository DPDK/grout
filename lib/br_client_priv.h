// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CLIENT_PRIV
#define _BR_CLIENT_PRIV

#include <stddef.h>
#include <stdint.h>

struct br_client {
	int sock_fd;
};

int send_recv(
	const struct br_client *,
	uint32_t req_type,
	size_t tx_len,
	const void *tx_data,
	void **rx_data
);

#endif
