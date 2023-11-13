// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include <bro_api.h>
#include <bro_client.h>
#include <bro_platform.h>

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

int send_recv(uint32_t type, void *req, size_t req_len, void *resp, size_t resp_len) {
	static uint8_t buf[BRO_API_BUF_SIZE];
	struct bro_api_header *header;
	ssize_t n, len;

	header = (struct bro_api_header *)buf;
	header->version = BRO_API_VERSION;
	header->status = 0;
	header->type = type;
	header->payload_len = req_len;
	if (req_len > 0)
		memcpy(header + 1, req, req_len);

	len = sizeof(*header) + req_len;
	n = send(api_sock, buf, len, 0);
	if (n < 0) {
		ERR("send: %s", strerror(errno));
		return -1;
	}
	if (n < (ssize_t)len) {
		ERR("send: %zi bytes not sent", len - n);
		return -1;
	}

	len = sizeof(*header) + resp_len;
	n = recv(api_sock, buf, len, 0);
	if (n < 0) {
		ERR("recv: %s", strerror(errno));
		return -1;
	}
	if (n != (ssize_t)len) {
		ERR("recv: expected %zu bytes, got %zi", len, n);
		return -1;
	}
	if (header->version != BRO_API_VERSION) {
		ERR("wrong api version: expected %u, got %u", BRO_API_VERSION, header->version);
		return -1;
	}
	if (header->status != 0) {
		ERR("%s", strerror(header->status));
		return -1;
	}
	if (header->type != type) {
		ERR("wrong response type: expected %u, got %u", type, header->type);
		return -1;
	}
	if (header->payload_len != resp_len) {
		ERR("wrong payload length: expected %zu, got %u", resp_len, header->payload_len);
		return -1;
	}
	if (resp_len > 0 && resp != NULL)
		memcpy(resp, header + 1, resp_len);

	return 0;
}

static cmdline_parse_ctx_t *cli_context;

void register_commands(cmdline_parse_ctx_t *ctx) {
	size_t n, add_len;

	if (ctx == NULL) {
		ERR("ctx cannot be NULL");
		abort();
	}

	if (cli_context != NULL) {
		for (n = 0; cli_context[n] != NULL; n++) {
			if (n > 9999) {
				ERR("cli_context not NULL terminated");
				abort();
			}
		}
	}

	for (add_len = 0; ctx[add_len] != NULL; add_len++) {
		if (add_len > 9999) {
			ERR("ctx array not NULL terminated");
			abort();
		}
	}

	// add 1 for NULL terminator
	cli_context = realloc(cli_context, sizeof(cmdline_parse_ctx_t *) * (n + add_len + 1));
	if (cli_context == NULL) {
		ERR("out of memory");
		abort();
	}

	memcpy(&cli_context[n], ctx, add_len);

	// NULL terminator
	cli_context[n + add_len] = NULL;
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
	cmdline_free(cl);
	if (api_sock != -1)
		close(api_sock);
	return ret;
}
