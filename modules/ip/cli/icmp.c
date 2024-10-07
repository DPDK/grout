// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_ip4.h>
#include <gr_net_types.h>

#include <ecoli.h>
#include <rte_icmp.h>
#include <rte_ip.h>

#include <errno.h>
#include <signal.h>
#include <sys/queue.h>
#include <unistd.h>

static const char *ICMP_DEST_UNREACHABLE[] = {
	"net unreachable",
	"host unreachable",
	"protocol unreachable"
	"port unreachable",
	"fragmentation needed and DF set",
	"source route failed",
};

static bool stop;

static void sighandler(int) {
	stop = true;
}

static cmd_status_t icmp_request(
	const struct gr_api_client *c,
	struct gr_ip4_ping_start_req *req,
	uint16_t msdelay,
	uint16_t count,
	bool mode_traceroute
) {
	cmd_status_t ret_code = CMD_SUCCESS;
	struct gr_ip4_icmp_get_reply_req reply_req;
	struct gr_ip4_ping_start_resp *start_resp;
	struct gr_ip4_icmp_get_reply_resp *reply_resp;
	void *resp_ptr = NULL;
	int timeout;
	int ret;

	for (int i = mode_traceroute; i < count && stop == false; i++) {
		req->ttl = (mode_traceroute ? i : 64);
		req->sequence_number = i;

		if (gr_api_client_send_recv(c, GR_IP4_ICMP_REQUEST, sizeof(*req), req, &resp_ptr)
		    < 0) {
			ret_code = CMD_ERROR;
			goto exit;
		}
		start_resp = resp_ptr;
		reply_req.id = start_resp->id;
		free(resp_ptr);

		timeout = 50;
		resp_ptr = NULL;
		do {
			usleep(10000);
			ret = gr_api_client_send_recv(
				c, GR_IP4_ICMP_GET_REPLY, sizeof(reply_req), &reply_req, &resp_ptr
			);
			reply_resp = resp_ptr;
			if (reply_resp && reply_resp->answered)
				break;
		} while (ret == 0 && --timeout);

		if (ret < 0) {
			ret_code = CMD_ERROR;
			goto exit;
		}

		reply_resp = resp_ptr;
		if (reply_resp == NULL || timeout == 0) {
			printf("Timeout\n");
			errno = ETIMEDOUT;
			ret_code = CMD_ERROR;
		} else {
			switch (reply_resp->type) {
			case RTE_IP_ICMP_ECHO_REPLY:
				if (mode_traceroute) {
					printf("(%d) " IP4_ADDR_FMT " time=%.3fms\n",
					       i,
					       IP4_ADDR_SPLIT(&req->addr),
					       reply_resp->response_time / 1000.);
					stop = true;

				} else {
					printf("icmp_seq=%d ttl=%d time=%.3fms\n",
					       reply_resp->sequence_number,
					       reply_resp->ttl,
					       reply_resp->response_time / 1000.);
				}
				break;
			case GR_IP_ICMP_DEST_UNREACHABLE:
				printf("Destination unreachable: %s\n",
				       ICMP_DEST_UNREACHABLE[reply_resp->code]);
				break;
			case GR_IP_ICMP_TTL_EXCEEDED:
				struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)reply_resp->data;
				printf("(%d) " IP4_ADDR_FMT " time=%.3fms\n",
				       hdr->time_to_live,
				       IP4_ADDR_SPLIT(&hdr->src_addr),
				       reply_resp->response_time / 1000.);
				break;
			}
			free(resp_ptr);
			usleep(msdelay * 1000);
		}
	}
exit:
	return ret_code;
}

static cmd_status_t ping(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_ping_start_req req = {.sequence_number = 0};
	cmd_status_t ret_code = CMD_SUCCESS;
	uint16_t msdelay = 1000;
	uint16_t count = 4;

	if (inet_pton(AF_INET, arg_str(p, "IP"), &req.addr) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	stop = false;
	sighandler_t prev_handler = signal(SIGINT, sighandler);
	if (prev_handler == SIG_ERR) {
		return CMD_ERROR;
	}

	if (arg_u16(p, "VRF", &req.vrf) < 0)
		req.vrf = 0;
	if (arg_u16(p, "COUNT", &count) < 0)
		count = 4;
	if (arg_u16(p, "DELAY", &msdelay) < 0)
		msdelay = 1000;

	req.ttl = 64;
	ret_code = icmp_request(c, &req, msdelay, count, false);

	signal(SIGINT, prev_handler);
	return ret_code;
}

static cmd_status_t traceroute(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip4_ping_start_req req = {.sequence_number = 0};
	cmd_status_t ret_code = CMD_SUCCESS;

	if (inet_pton(AF_INET, arg_str(p, "IP"), &req.addr) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}

	stop = false;
	sighandler_t prev_handler = signal(SIGINT, sighandler);
	if (prev_handler == SIG_ERR) {
		return CMD_ERROR;
	}

	if (arg_u16(p, "VRF", &req.vrf) < 0)
		req.vrf = 0;

	ret_code = icmp_request(c, &req, 0, 255, true);

	signal(SIGINT, prev_handler);
	return ret_code;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("ping", "IPv4 icmp request")),
		"IP [vrf VRF] [count COUNT] [delay DELAY]",
		ping,
		"Send ICMP request to destination IP.",
		with_help("IPv4 address.", ec_node_re("IP", IPV4_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10)),
		with_help("Number of packets to send.", ec_node_uint("COUNT", 1, 10000, 10)),
		with_help("Delay in ms between icmp echo.", ec_node_uint("DELAY", 0, 10000, 10))
	);

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("traceroute", "traceroute IPv4 icmp request")),
		"IP [vrf VRF]",
		traceroute,
		"Send ICMP request to destination IP.",
		with_help("IPv4 address.", ec_node_re("IP", IPV4_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10))
	);

	return ret;
}

static struct gr_cli_context ctx = {
	.name = "ping",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
