// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "cli.h"

#include <bro_client.h>
#include <bro_platform.h>

#include <cmdline.h>
#include <rte_ethdev.h>

#include <sys/socket.h>

void cmd_quit_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	(void)parsed_result;
	(void)data;
	cmdline_quit(cl);
}

RTE_INIT(platform_cli_init) {
	register_commands(commands_context);
}
