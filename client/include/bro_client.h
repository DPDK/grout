// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BROUTER_CLIENT
#define _BROUTER_CLIENT

#include <cmdline.h>

#include <stddef.h>
#include <stdint.h>

// register commands for the interactive client
// should be called in RTE_INIT or any __attribute__((constructor)) function
// must be a NULL terminated array of cmdline_parse_inst_t*
void register_commands(cmdline_parse_ctx_t *ctx);

// send a command to the server and receive a response
int send_recv(uint32_t type, void *req, size_t req_len, void *resp, size_t resp_len);

#define ERR(fmt, ...)                                                                              \
	do {                                                                                       \
		static_assert(                                                                     \
			!__builtin_strchr(fmt, '\n'), "This log format string contains a \\n"      \
		);                                                                                 \
		fprintf(stderr, "error: " fmt "\n" __VA_OPT__(, ) __VA_ARGS__);                    \
	} while (0)

#endif
