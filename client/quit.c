// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "quit.h"

#include <br_client.h>

#include <cmdline.h>
#include <rte_ethdev.h>

#include <sys/socket.h>

void cmd_quit_parsed(void *parsed_result, struct cmdline *cl, void *data) {
	(void)parsed_result;
	(void)data;
	cmdline_quit(cl);
}

RTE_INIT(infra_cli_init) {
	BR_REGISTER_COMMANDS(commands_context);
}
