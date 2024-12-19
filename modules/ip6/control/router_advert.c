// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_api.h>
#include <gr_control_input.h>
#include <gr_iface.h>
#include <gr_ip6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_mempool.h>
#include <gr_module.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

struct ra_ctx {
	struct rte_mempool *mp;
	struct event *timer;
};

static struct ra_ctx ra_ctx;
static control_input_t ra_output;

static struct api_out iface_ra_set(const void *request, void ** /*response*/) {
	const struct gr_ip6_ra_set_req *req = request;
	if (iface_from_id(req->iface_id) == NULL)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct api_out iface_ra_clear(const void *request, void ** /*response*/) {
	const struct gr_ip6_ra_clear_req *req = request;
	if (iface_from_id(req->iface_id) == NULL)
		return api_out(errno, 0);

	return api_out(0, 0);
}

void ndp_router_sollicit_input_cb(struct rte_mbuf *m) {
	rte_pktmbuf_free(m);
	event_active(ra_ctx.timer, 0, 0);
}

static void build_ra_packet(struct rte_mbuf *m, struct rte_ipv6_addr *srcv6) {
	struct rte_ipv6_addr dst = RTE_IPV6_ADDR_ALLNODES_LINK_LOCAL;
	struct rte_ipv6_addr src = *srcv6;
	struct icmp6_opt_lladdr *lladdr;
	struct icmp6_router_advert *ra;
	struct rte_ether_addr mac;
	struct rte_ipv6_hdr *ip;
	struct icmp6_opt *opt;
	uint16_t payload_len;
	struct icmp6 *icmp6;
	uint16_t iface_id;
	uint16_t vrf_id;

	vrf_id = mbuf_data(m)->iface->vrf_id;
	iface_id = mbuf_data(m)->iface->id;
	ip6_output_mbuf_data(m)->nh = ip6_nexthop_lookup(vrf_id, iface_id, &dst);
	ip = (struct rte_ipv6_hdr *)rte_pktmbuf_append(m, sizeof(*ip));
	icmp6 = (struct icmp6 *)rte_pktmbuf_append(m, sizeof(*icmp6));
	icmp6->type = ICMP6_TYPE_ROUTER_ADVERT;
	icmp6->code = 0;
	ra = (struct icmp6_router_advert *)rte_pktmbuf_append(m, sizeof(*ra));
	ra->cur_hoplim = IP6_DEFAULT_HOP_LIMIT; // Default TTL for this network
	ra->managed_addr = 0; // DHCPv6 is available
	ra->other_config = 0; // DNS available, ...
	ra->lifetime = RTE_BE16(0); // Not a default router
	ra->reachable_time = RTE_BE16(0);
	ra->retrans_timer = RTE_BE16(0);

	payload_len = sizeof(*icmp6) + sizeof(*ra);

	if (iface_get_eth_addr(mbuf_data(m)->iface->id, &mac) == 0) {
		opt = (struct icmp6_opt *)rte_pktmbuf_append(m, sizeof(*opt));
		opt->type = ICMP6_OPT_SRC_LLADDR;
		opt->len = ICMP6_OPT_LEN(sizeof(*opt) + sizeof(*lladdr));
		lladdr = (struct icmp6_opt_lladdr *)rte_pktmbuf_append(m, sizeof(*lladdr));
		lladdr->mac = mac;
		payload_len += sizeof(*opt) + sizeof(*lladdr);
	}

	ip6_set_fields(ip, payload_len, IPPROTO_ICMPV6, &src, &dst);
	icmp6->cksum = 0;
	icmp6->cksum = rte_ipv6_udptcp_cksum(ip, icmp6);
}

static void send_ra_cb(evutil_socket_t, short /*what*/, void * /*priv*/) {
	struct iface *iface = NULL;
	struct rte_mbuf *m;

	while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
		struct hoplist *hl = ip6_addr_get_all(iface->id);
		if (hl == NULL)
			continue;
		for (unsigned i = 0; i < gr_vec_len(hl); i++) {
			struct nexthop *nh = hl->nh[i];
			struct rte_ipv6_addr ip = nh->ipv6;
			if (nh->family != AF_INET6)
				continue;
			if (!rte_ipv6_addr_is_linklocal(&ip))
				continue;

			if ((m = rte_pktmbuf_alloc(ra_ctx.mp)) == NULL) {
				LOG(ERR, "rte_pktmbuf_alloc");
				return;
			}
			mbuf_data(m)->iface = iface;
			build_ra_packet(m, &ip);
			post_to_stack(ra_output, m);
		}
	}
}

static void ra_init(struct event_base *ev_base) {
	ra_output = gr_control_input_register_handler("ip6_output", true);
	ra_ctx.mp = gr_pktmbuf_pool_get(SOCKET_ID_ANY, 512);
	if (ra_ctx.mp == NULL) {
		ABORT("gr_pktmbuf_pool_get ENOMEM");
	}

	ra_ctx.timer = event_new(ev_base, -1, EV_PERSIST, send_ra_cb, NULL);
	if (ra_ctx.timer == NULL) {
		ABORT("event_new() failed");
	}

	if (event_add(ra_ctx.timer, &(struct timeval) {.tv_sec = 600}) < 0) {
		ABORT("event_add() failed");
	}
}

static void ra_fini(struct event_base * /*ev_base*/) {
	gr_pktmbuf_pool_release(ra_ctx.mp, 512);
	event_free(ra_ctx.timer);
}

static struct gr_module ra_module = {
	.name = "ipv6 router advertisement",
	.init = ra_init,
	.fini = ra_fini,
	.fini_prio = 20000,
};

static struct gr_api_handler ra_set_handler = {
	.name = "set interface ra",
	.request_type = GR_IP6_IFACE_RA_SET,
	.callback = iface_ra_set,
};

static struct gr_api_handler ra_clear_handler = {
	.name = "clear interface ra",
	.request_type = GR_IP6_IFACE_RA_CLEAR,
	.callback = iface_ra_clear,
};

RTE_INIT(router_advertisement_init) {
	gr_register_module(&ra_module);
	gr_register_api_handler(&ra_set_handler);
	gr_register_api_handler(&ra_clear_handler);
}
