// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 SmartShare Systems

// clang-format off
#include <gr_api_client_impl.h>
// clang-format on

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ping(struct gr_api_client *c, uint32_t count, size_t payload_len) {
	void *buf = NULL;

	if (payload_len > 0) {
		buf = calloc(1, payload_len);
		if (buf == NULL)
			return -1;
	}

	for (uint32_t i = 0; i < count; i++) {
		void *resp = NULL;
		if (gr_api_client_send_recv(c, GR_PING, payload_len, buf, &resp) < 0) {
			perror("GR_PING");
			free(buf);
			return -1;
		}
		free(resp);
	}

	free(buf);
	return 0;
}

static void usage(const char *prog) {
	fprintf(stderr, "Usage: %s [-s SOCK] [-n COUNT] [-l LEN]\n", prog);
	fprintf(stderr, "  -s SOCK    API socket path (default: $GROUT_SOCK_PATH)\n");
	fprintf(stderr, "  -n COUNT   Number of ping calls (default: 10000)\n");
	fprintf(stderr, "  -l LEN     Payload length in bytes (default: 0)\n");
}

int main(int argc, char **argv) {
	const char *sock_path = getenv("GROUT_SOCK_PATH");
	unsigned int count = 10000;
	struct gr_api_client *c;
	size_t payload_len = 0;
	gr_clock_ns_t time;
	float duration;
	int ret;
	int o;

	while ((o = getopt(argc, argv, "s:n:l:h")) != -1) {
		switch (o) {
		case 's':
			sock_path = optarg;
			break;
		case 'n':
			count = strtoul(optarg, NULL, 10);
			break;
		case 'l':
			payload_len = strtoul(optarg, NULL, 10);
			break;
		case 'h':
		default:
			usage(argv[0]);
			return o == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	}
	if (sock_path == NULL)
		sock_path = GR_DEFAULT_SOCK_PATH;

	c = gr_api_client_connect(sock_path);
	if (c == NULL) {
		perror("gr_api_client_connect");
		return EXIT_FAILURE;
	}

	printf("performing %u ping calls (payload %zu bytes)\n", count, payload_len);

	time = gr_clock_ns();
	ret = ping(c, count, payload_len);
	duration = (float)(gr_clock_ns() - time) / (float)GR_NS_PER_S;

	printf("total time: %.3f s (%.1f calls/s)\n", duration, (float)count / duration);

	gr_api_client_disconnect(c);

	return ret < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
