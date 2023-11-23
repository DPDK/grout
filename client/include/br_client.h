// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CLIENT
#define _BR_CLIENT

#include <br_api.h>

#include <cmdline.h>

// register commands for the interactive client
// should be called in RTE_INIT or any __attribute__((constructor)) function
// must be a NULL terminated array of cmdline_parse_inst_t*
void br_register_commands(cmdline_parse_ctx_t *ctx, size_t num);

#define BR_REGISTER_COMMANDS(ctx) br_register_commands(ctx, sizeof(ctx) / sizeof(ctx[0]) - 1)

// send a command to the server and receive a response
int br_send_recv(
	uint32_t req_type,
	size_t tx_len,
	const void *tx_data,
	size_t rx_len,
	void *rx_data
);

#define ERR(fmt, ...)                                                                              \
	do {                                                                                       \
		static_assert(                                                                     \
			!__builtin_strchr(fmt, '\n'), "This log format string contains a \\n"      \
		);                                                                                 \
		fprintf(stderr, "error: " fmt "\n" __VA_OPT__(, ) __VA_ARGS__);                    \
	} while (0)

#endif
