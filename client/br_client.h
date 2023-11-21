// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CLIENT
#define _BR_CLIENT

#include "../core/br_api.pb-c.h"

#include <cmdline.h>

// register commands for the interactive client
// should be called in RTE_INIT or any __attribute__((constructor)) function
// must be a NULL terminated array of cmdline_parse_inst_t*
void br_register_commands(cmdline_parse_ctx_t *ctx, size_t num);

#define BR_REGISTER_COMMANDS(ctx) br_register_commands(ctx, sizeof(ctx) / sizeof(ctx[0]) - 1)

// send a command to the server and receive a response
// caller needs to free the response with br__response__free_unpacked
Br__Response *br_send_recv(const Br__Request *);

uint64_t br_next_message_id(void);

#define ERR(fmt, ...)                                                                              \
	do {                                                                                       \
		static_assert(                                                                     \
			!__builtin_strchr(fmt, '\n'), "This log format string contains a \\n"      \
		);                                                                                 \
		fprintf(stderr, "error: " fmt "\n" __VA_OPT__(, ) __VA_ARGS__);                    \
	} while (0)

#endif
