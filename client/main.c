// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br_api.pb-c.h"

#include <br_api.h>
#include <br_client.h>

#include <cmdline.h>
#include <cmdline_socket.h>

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void usage(const char *prog) {
	printf("Usage: %s [-s PATH]\n", prog);
	puts("");
	puts("  Boring router client.");
	puts("");
	puts("options:");
	puts("  -h, --help                 Show this help message and exit.");
	puts("  -s PATH, --socket PATH     Path the control plane API socket.");
}

static const char *api_sock_path = "/run/brouter.sock";

static int parse_args(int argc, char **argv) {
	int c;

#define FLAGS "s:h"
	static struct option long_options[] = {
		{"socket", required_argument, NULL, 's'},
		{"help", no_argument, NULL, 'h'},
		{0},
	};

	while ((c = getopt_long(argc, argv, FLAGS, long_options, NULL)) != -1) {
		switch (c) {
		case 's':
			api_sock_path = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return -1;
		default:
			break;
		}
	}
	if (optind != argc) {
		ERR("invalid arguments");
		return -1;
	}

	return 0;
}

int api_sock;

static int connect_api_sock(void) {
	struct sockaddr_un addr = {.sun_family = AF_UNIX};

	api_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (api_sock == -1) {
		ERR("socket: %s", strerror(errno));
		return -1;
	}

	strncpy(addr.sun_path, api_sock_path, sizeof addr.sun_path - 1);

	if (connect(api_sock, (struct sockaddr *)&addr, sizeof addr) < 0) {
		ERR("connect: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static uint64_t message_id;

uint64_t br_next_message_id(void) {
	return ++message_id;
}

Br__Response *br_send_recv(const Br__Request *req) {
	static uint8_t buf[BR_MAX_MSG_LEN];
	Br__Response *resp = NULL;
	size_t len;
	ssize_t n;

	len = br__request__get_packed_size(req);
	if (len > sizeof(buf)) {
		ERR("request too large");
		goto free;
	}
	br__request__pack(req, buf);

	n = send(api_sock, buf, len, 0);
	if (n < 0) {
		ERR("send: %s", strerror(errno));
		goto free;
	}
	if (n < (ssize_t)len) {
		ERR("send: %zi bytes not sent", len - n);
		goto free;
	}

	n = recv(api_sock, buf, sizeof(buf), 0);
	if (n < 0) {
		ERR("recv: %s", strerror(errno));
		goto free;
	}

	resp = br__response__unpack(BR_PROTO_ALLOCATOR, n, buf);
	if (resp == NULL) {
		ERR("cannot unpack outer response");
		goto free;
	}
	if (resp->for_id != req->id) {
		ERR("invalid response id: expected %lu, got %lu", req->id, resp->for_id);
		goto free;
	}
	if (resp->status != 0) {
		ERR("%s", strerror(resp->status));
		goto free;
	}

	return resp;

free:
	br__response__free_unpacked(resp, BR_PROTO_ALLOCATOR);
	return NULL;
}

static size_t num_commands;
static cmdline_parse_ctx_t *cli_context;

void br_register_commands(cmdline_parse_ctx_t *ctx, size_t num) {
	size_t new_num = num_commands + num;

	// add 1 for NULL terminator
	cli_context = realloc(cli_context, sizeof(cmdline_parse_ctx_t) * (new_num + 1));
	if (cli_context == NULL) {
		ERR("out of memory");
		abort();
	}

	memcpy(&cli_context[num_commands], ctx, sizeof(cmdline_parse_ctx_t) * num);

	// NULL terminator
	cli_context[new_num] = NULL;
	num_commands = new_num;
}

int main(int argc, char **argv) {
	int ret = EXIT_FAILURE;
	struct cmdline *cl = NULL;

	api_sock = -1;

	if (parse_args(argc, argv) < 0)
		goto end;

	if (connect_api_sock() < 0)
		goto end;

	if ((cl = cmdline_stdin_new(cli_context, "brouter# ")) == NULL) {
		ERR("failed initializing command line");
		goto end;
	}

	cmdline_interact(cl);
	cmdline_stdin_exit(cl);
	fputc('\n', stdout);

	ret = EXIT_SUCCESS;
end:
	if (api_sock != -1)
		close(api_sock);
	return ret;
}
