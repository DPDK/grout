// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_ip4.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <signal.h>
#include <sys/queue.h>
#include <unistd.h>

static const char *icmp_dest_unreachable[] = {
	[RTE_ICMP_CODE_UNREACH_NET] = "net unreachable",
	[RTE_ICMP_CODE_UNREACH_HOST] = "host unreachable",
	[RTE_ICMP_CODE_UNREACH_PROTO] = "protocol unreachable",
	[RTE_ICMP_CODE_UNREACH_PORT] = "port unreachable",
	[RTE_ICMP_CODE_UNREACH_FRAG] = "fragmentation needed and DF set",
	[RTE_ICMP_CODE_UNREACH_SRC] = "source route failed",
};

static bool stop;

static void sighandler(int) {
	stop = true;
}

static cmd_status_t icmp_send(
	struct gr_api_client *c,
	struct gr_ip4_icmp_send_req *req,
	uint16_t msdelay,
	uint16_t count,
	uint16_t ident,
	bool mode_traceroute
) {
	struct gr_ip4_icmp_recv_resp *reply_resp;
	struct gr_ip4_icmp_recv_req reply_req;
	int timeout, ret, errors;
	void *resp_ptr = NULL;

	stop = false;
	errors = 0;
	errno = 0;

	for (int i = mode_traceroute; i < count && stop == false; i++) {
		req->ttl = mode_traceroute ? i : 64;
		req->ident = ident;
		req->seq_num = i;

		ret = gr_api_client_send_recv(c, GR_IP4_ICMP_SEND, sizeof(*req), req, NULL);
		if (ret < 0)
			return CMD_ERROR;

		reply_req.ident = ident;
		reply_req.seq_num = i;
		timeout = 50;
		do {
			usleep(10000);
			ret = gr_api_client_send_recv(
				c, GR_IP4_ICMP_RECV, sizeof(reply_req), &reply_req, &resp_ptr
			);
			if (resp_ptr != NULL)
				break;
		} while (ret == 0 && --timeout > 0);

		if (ret < 0)
			return CMD_ERROR;

		reply_resp = resp_ptr;
		if (reply_resp == NULL || timeout == 0) {
			errors++;
			errno = ETIMEDOUT;
			if (mode_traceroute)
				printf("%2d  timeout\n", i);
			else
				printf("timeout: icmp_seq=%d\n", i);
		} else {
			switch (reply_resp->type) {
			case RTE_ICMP_TYPE_ECHO_REPLY:
				if (mode_traceroute) {
					printf("%2d  " IP4_F " time=%.3f ms\n",
					       i,
					       &reply_resp->src_addr,
					       reply_resp->response_time / 1000.);
					stop = true;
					errors = 0;
					errno = 0;
				} else {
					printf("reply from " IP4_F ": icmp_seq=%d ttl=%d "
					       "time=%.3f ms\n",
					       &reply_resp->src_addr,
					       reply_resp->seq_num,
					       reply_resp->ttl,
					       reply_resp->response_time / 1000.);
				}
				break;
			case RTE_ICMP_TYPE_DEST_UNREACHABLE:
				errors++;
				errno = EHOSTUNREACH;
				printf("reply from " IP4_F ": icmp_seq=%d ttl=%d: %s\n",
				       &reply_resp->src_addr,
				       reply_resp->seq_num,
				       reply_resp->ttl,
				       icmp_dest_unreachable[reply_resp->code]);
				break;
			case RTE_ICMP_TYPE_TTL_EXCEEDED:
				errors++;
				errno = ETIMEDOUT;
				printf("%2d  " IP4_F " time=%.3f ms\n",
				       i,
				       &reply_resp->src_addr,
				       reply_resp->response_time / 1000.);
				break;
			}
			free(resp_ptr);
			resp_ptr = NULL;
		}
		usleep(msdelay * 1000);
	}

	if (!stop && errors > 0)
		return CMD_ERROR;

	return CMD_SUCCESS;
}

static cmd_status_t ping(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_icmp_send_req req = {.seq_num = 0, .vrf = 0};
	cmd_status_t ret = CMD_ERROR;
	uint16_t count = UINT16_MAX;
	uint16_t ident = random();
	uint16_t msdelay = 1000;

	if (arg_ip4(p, "IP", &req.addr) < 0)
		return CMD_ERROR;
	if ((ret = arg_u16(p, "VRF", &req.vrf)) < 0 && ret != ENOENT)
		return CMD_ERROR;
	if ((ret = arg_u16(p, "COUNT", &count)) < 0 && ret != ENOENT)
		return CMD_ERROR;
	if ((ret = arg_u16(p, "DELAY", &msdelay)) < 0 && ret != ENOENT)
		return CMD_ERROR;
	if ((ret = arg_u16(p, "IDENT", &ident)) < 0 && ret != ENOENT)
		return CMD_ERROR;

	sighandler_t prev_handler = signal(SIGINT, sighandler);
	if (prev_handler == SIG_ERR)
		return CMD_ERROR;

	ret = icmp_send(c, &req, msdelay, count, ident, false);

	signal(SIGINT, prev_handler);

	return ret;
}

static cmd_status_t traceroute(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_icmp_send_req req = {.seq_num = 0, .vrf = 0};
	cmd_status_t ret = CMD_SUCCESS;
	uint16_t ident = random();

	if (arg_ip4(p, "IP", &req.addr) < 0)
		return CMD_ERROR;
	if ((ret = arg_u16(p, "IDENT", &ident)) < 0 && ret != ENOENT)
		return CMD_ERROR;
	if ((ret = arg_u16(p, "VRF", &req.vrf)) < 0 && ret != ENOENT)
		return CMD_ERROR;

	sighandler_t prev_handler = signal(SIGINT, sighandler);
	if (prev_handler == SIG_ERR)
		return CMD_ERROR;

	ret = icmp_send(c, &req, 0, 255, ident, true);

	signal(SIGINT, prev_handler);

	return ret;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(
			root, CTX_ARG("ping", "Send IPv4 ICMP echo requests and wait for replies.")
		),
		"IP [(vrf VRF),(count COUNT),(delay DELAY),(ident IDENT)]",
		ping,
		"Send IPv4 ICMP echo requests and wait for replies.",
		with_help("IPv4 destination address.", ec_node_re("IP", IPV4_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10)),
		with_help("Number of packets to send.", ec_node_uint("COUNT", 1, UINT16_MAX, 10)),
		with_help("Delay in ms between icmp echo.", ec_node_uint("DELAY", 0, 10000, 10)),
		with_help(
			"Icmp ident field (default: random).",
			ec_node_uint("IDENT", 1, UINT16_MAX, 10)
		)
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("traceroute", "Discover IPv4 intermediate gateways.")),
		"IP [(ident IDENT),(vrf VRF)]",
		traceroute,
		"Discover IPv4 intermediate gateways.",
		with_help("IPv4 destination address.", ec_node_re("IP", IPV4_RE)),
		with_help(
			"Icmp ident field (default: random).",
			ec_node_uint("IDENT", 1, UINT16_MAX, 10)
		),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);

	return ret;
}

static struct cli_context ctx = {
	.name = "ping",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
