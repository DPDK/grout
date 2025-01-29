// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_iface.h>
#include <gr_ip6.h>
#include <gr_net_types.h>

#include <ecoli.h>

#include <errno.h>
#include <signal.h>
#include <sys/queue.h>
#include <unistd.h>

static bool stop;

static void sighandler(int) {
	stop = true;
}

static cmd_status_t icmp_send(
	const struct gr_api_client *c,
	struct gr_ip6_icmp_send_req *req,
	uint16_t msdelay,
	uint16_t count,
	bool mode_traceroute
) {
	struct gr_ip6_icmp_recv_resp *reply_resp;
	struct gr_ip6_icmp_recv_req reply_req;
	int i, timeout, ret, errors;
	void *resp_ptr = NULL;
	uint16_t ping_id;
	const char *errdesc;

	stop = false;
	errors = 0;
	errno = 0;
	ping_id = random();

	for (i = !!mode_traceroute; i < count && stop == false; i++) {
		req->id = ping_id;
		req->seq_num = i;
		req->ttl = mode_traceroute ? i : 64;

		ret = gr_api_client_send_recv(c, GR_IP6_ICMP6_SEND, sizeof(*req), req, &resp_ptr);
		if (ret < 0)
			return CMD_ERROR;
		free(resp_ptr);
		resp_ptr = NULL;

		reply_req.id = ping_id;
		reply_req.seq_num = i;
		timeout = 50;
		do {
			usleep(10000);
			ret = gr_api_client_send_recv(
				c, GR_IP6_ICMP6_RECV, sizeof(reply_req), &reply_req, &resp_ptr
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
			case ICMP6_TYPE_ECHO_REPLY:
				if (!mode_traceroute) {
					printf("reply from " IP6_F ": icmp_seq=%d ttl=%d "
					       "time=%.3f ms\n",
					       &reply_resp->src_addr,
					       reply_resp->seq_num,
					       reply_resp->ttl,
					       reply_resp->response_time / 1000.);
				} else {
					printf("%2d  " IP6_F " time=%.3f ms\n",
					       i,
					       &reply_resp->src_addr,
					       reply_resp->response_time / 1000.);
					stop = true;
					errors = 0;
				}
				errno = 0;
				break;
			case ICMP6_TYPE_ERR_DEST_UNREACH:
				errno = EHOSTUNREACH;
				errdesc = " destination unreachable";
				break;
			case ICMP6_TYPE_ERR_PKT_TOO_BIG:
				errno = EINVAL;
				errdesc = " packet too big";
				break;
			case ICMP6_TYPE_ERR_TTL_EXCEEDED:
				errno = ETIMEDOUT;
				errdesc = " ttl exceeded";
				break;
			case ICMP6_TYPE_ERR_PARAM_PROBLEM:
			default:
				errno = EINVAL;
				errdesc = " parameter problem";
				break;
			}
			if (errno && !mode_traceroute) {
				errors++;
				printf("reply from " IP6_F ": icmp_seq=%d ttl=%d:%s\n",
				       &reply_resp->src_addr,
				       reply_resp->seq_num,
				       reply_resp->ttl,
				       errdesc);
			} else if (errno && mode_traceroute) {
				errors++;
				if (errno == ETIMEDOUT)
					errdesc = "";
				printf("%2d  " IP6_F " time=%.3f ms%s\n",
				       i,
				       &reply_resp->src_addr,
				       reply_resp->response_time / 1000.,
				       errdesc);
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

static cmd_status_t ping(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_icmp_send_req req = {.iface = GR_IFACE_ID_UNDEF, .vrf = 0};
	cmd_status_t ret = CMD_ERROR;
	uint16_t count = UINT16_MAX;
	uint16_t msdelay = 1000;
	struct gr_iface iface;
	const char *str;

	if (inet_pton(AF_INET6, arg_str(p, "DEST"), &req.addr) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	if ((ret = arg_u16(p, "VRF", &req.vrf)) < 0 && ret != ENOENT)
		return CMD_ERROR;
	if ((ret = arg_u16(p, "COUNT", &count)) < 0 && ret != ENOENT)
		return CMD_ERROR;
	if ((ret = arg_u16(p, "DELAY", &msdelay)) < 0 && ret != ENOENT)
		return CMD_ERROR;
	if ((str = arg_str(p, "IFACE")) != NULL) {
		if (iface_from_name(c, str, &iface) < 0)
			return CMD_ERROR;
		req.iface = iface.id;
	}

	sighandler_t prev_handler = signal(SIGINT, sighandler);
	if (prev_handler == SIG_ERR)
		return CMD_ERROR;

	ret = icmp_send(c, &req, msdelay, count, false);

	signal(SIGINT, prev_handler);

	return ret;
}

static cmd_status_t traceroute(const struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_ip6_icmp_send_req req = {.iface = GR_IFACE_ID_UNDEF, .vrf = 0};
	cmd_status_t ret = CMD_SUCCESS;
	struct gr_iface iface;
	const char *str;

	if (inet_pton(AF_INET6, arg_str(p, "DEST"), &req.addr) != 1) {
		errno = EINVAL;
		return CMD_ERROR;
	}
	if ((ret = arg_u16(p, "VRF", &req.vrf)) < 0 && ret != ENOENT)
		return CMD_ERROR;
	if ((str = arg_str(p, "IFACE")) != NULL) {
		if (iface_from_name(c, str, &iface) < 0)
			return CMD_ERROR;
		req.iface = iface.id;
	}

	sighandler_t prev_handler = signal(SIGINT, sighandler);
	if (prev_handler == SIG_ERR)
		return CMD_ERROR;

	ret = icmp_send(c, &req, 0, 255, true);

	signal(SIGINT, prev_handler);

	return ret;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(
			root, CTX_ARG("ping", "Send ICMPv6 echo requests and wait for replies.")
		),
		"DEST [vrf VRF] [count COUNT] [delay DELAY] [iface IFACE]",
		ping,
		"Send ICMPv6 echo requests and wait for replies.",
		with_help("IPv6 destination address.", ec_node_re("DEST", IPV6_RE)),
		with_help(
			"Output interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10)),
		with_help("Number of packets to send.", ec_node_uint("COUNT", 1, UINT16_MAX, 10)),
		with_help("Delay in ms between icmp6 echo.", ec_node_uint("DELAY", 0, 10000, 10))
	);
	if (ret < 0)
		return ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("traceroute", "Discover IPv6 intermediate gateways.")),
		"DEST [vrf VRF] [iface IFACE]",
		traceroute,
		"Discover IPv6 intermediate gateways.",
		with_help("IPv6 destination address.", ec_node_re("DEST", IPV6_RE)),
		with_help("L3 routing domain ID.", ec_node_uint("VRF", 0, UINT16_MAX - 1, 10)),
		with_help(
			"Output interface name.",
			ec_node_dyn("IFACE", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		)
	);

	return ret;
}

static struct gr_cli_context ctx = {
	.name = "ping6",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
