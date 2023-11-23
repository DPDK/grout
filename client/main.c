// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

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

static uint32_t message_id;

int br_send_recv(
	uint32_t req_type,
	size_t tx_len,
	const void *tx_data,
	size_t rx_len,
	void *rx_data
) {
	uint8_t buf[BR_API_MAX_MSG_LEN];
	struct br_api_request *req = (void *)buf;
	struct br_api_response *resp = (void *)buf;
	uint32_t id = ++message_id;
	ssize_t n;

	req->id = id;
	req->type = req_type;
	req->payload_len = tx_len;
	if (tx_len > 0)
		memcpy(PAYLOAD(req), tx_data, tx_len);

	if (send(api_sock, req, sizeof(*req) + tx_len, 0) < 0) {
		ERR("send: %s", strerror(errno));
		return -1;
	}

	n = recv(api_sock, resp, sizeof(buf), 0);
	if (n < 0) {
		ERR("recv: %s", strerror(errno));
		return -1;
	}
	if ((size_t)n != sizeof(*resp) + rx_len) {
		ERR("invalid response size: expected %zu, got %zu", sizeof(*resp) + rx_len, n);
		return -1;
	}
	if (resp->for_id != id) {
		ERR("invalid response id: expected %u, got %u", id, resp->for_id);
		return -1;
	}
	if (resp->status != 0) {
		ERR("%s", strerror(resp->status));
		return -1;
	}
	if (resp->payload_len != rx_len) {
		ERR("invalid payload size: expected %zu, got %u", rx_len, resp->payload_len);
		return -1;
	}
	if (rx_len > 0)
		memcpy(rx_data, PAYLOAD(resp), rx_len);

	return 0;
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
