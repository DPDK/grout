// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#include <gr_api.h>
#include <gr_control_input.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_ip6.h>
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

#define RA_DEFAULT_INTERVAL 600
#define RA_DEFAULT_LIFETIME 1800

struct ra_ctx {
	struct rte_mempool *mp;
};

static struct ra_ctx ra_ctx;
static control_input_t ra_output;
static struct event_base *ev_base;

struct ra_iface_conf {
	struct event *timer;
	bool enabled;
	uint16_t interval;
	uint16_t lifetime;
};

static struct ra_iface_conf ra_conf[MAX_IFACES];

static struct api_out iface_ra_set(const void *request, void ** /*response*/) {
	const struct gr_ip6_ra_set_req *req = request;

	if (iface_from_id(req->iface_id) == NULL)
		return api_out(errno, 0);

	if (req->set_interval)
		ra_conf[req->iface_id].interval = req->interval;
	if (req->set_lifetime)
		ra_conf[req->iface_id].lifetime = req->lifetime;

	event_add(
		ra_conf[req->iface_id].timer,
		&(struct timeval) {.tv_sec = ra_conf[req->iface_id].interval}
	);
	event_active(ra_conf[req->iface_id].timer, 0, 0);
	return api_out(0, 0);
}

static struct api_out iface_ra_clear(const void *request, void ** /*response*/) {
	const struct gr_ip6_ra_clear_req *req = request;

	if (iface_from_id(req->iface_id) == NULL)
		return api_out(errno, 0);

	event_del(ra_conf[req->iface_id].timer);
	ra_conf[req->iface_id].interval = RA_DEFAULT_INTERVAL;
	ra_conf[req->iface_id].lifetime = RA_DEFAULT_LIFETIME;

	return api_out(0, 0);
}

static struct api_out iface_ra_show(const void *request, void **response) {
	const struct gr_ip6_ra_show_req *req = request;
	struct gr_ip6_ra_show_resp *resp;
	uint16_t iface_id, n_ras;
	struct hoplist *addrs;
	bool show_all = false;
	size_t len;

	if (req->iface_id == 0)
		show_all = true;
	else if (iface_from_id(req->iface_id) == NULL)
		return api_out(errno, 0);

	n_ras = 0;
	for (iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		addrs = addr6_get_all(iface_id);
		if (addrs == NULL || gr_vec_len(addrs->nh) == 0)
			continue;
		if (show_all == false && iface_id != req->iface_id)
			continue;
		n_ras++;
	}

	len = sizeof(*resp) + n_ras * sizeof(struct gr_ip6_ra_conf);
	resp = calloc(1, sizeof(*resp) + n_ras * sizeof(struct gr_ip6_ra_conf));
	if (!resp)
		return api_out(ENOMEM, 0);
	resp->n_ras = n_ras;
	n_ras = 0;
	for (uint16_t iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		addrs = addr6_get_all(iface_id);
		if (addrs == NULL || gr_vec_len(addrs->nh) == 0)
			continue;
		if (show_all == false && iface_id != req->iface_id)
			continue;

		resp->ras[n_ras].iface_id = iface_id;
		resp->ras[n_ras].enabled = event_pending(
			ra_conf[iface_id].timer, EV_TIMEOUT | EV_READ | EV_WRITE | EV_SIGNAL, 0
		);
		resp->ras[n_ras].interval = ra_conf[iface_id].interval;
		resp->ras[n_ras].lifetime = ra_conf[iface_id].lifetime;
		n_ras++;
	}

	*response = resp;
	return api_out(0, len);
}

void ndp_router_sollicit_input_cb(struct rte_mbuf *m) {
	uint16_t iface_id = mbuf_data(m)->iface->id;
	rte_pktmbuf_free(m);
	event_active(ra_conf[iface_id].timer, 0, 0);
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
	ip6_output_mbuf_data(m)->nh = nh6_lookup(vrf_id, iface_id, &dst);
	ip = (struct rte_ipv6_hdr *)rte_pktmbuf_append(m, sizeof(*ip));
	icmp6 = (struct icmp6 *)rte_pktmbuf_append(m, sizeof(*icmp6));
	icmp6->type = ICMP6_TYPE_ROUTER_ADVERT;
	icmp6->code = 0;
	ra = (struct icmp6_router_advert *)rte_pktmbuf_append(m, sizeof(*ra));
	ra->cur_hoplim = IP6_DEFAULT_HOP_LIMIT; // Default TTL for this network
	ra->managed_addr = 0; // DHCPv6 is available
	ra->other_config = 0; // DNS available, ...
	ra->lifetime = rte_cpu_to_be_16(ra_conf[iface_id].lifetime);
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

static void send_ra_cb(evutil_socket_t, short /*what*/, void *priv) {
	struct iface *iface = priv;
	struct hoplist *hl;
	struct nexthop *nh;
	struct rte_mbuf *m;

	if ((hl = addr6_get_all(iface->id)) == NULL)
		return;

	gr_vec_foreach (nh, hl->nh) {
		struct rte_ipv6_addr ip = nh->ipv6;
		if (nh->type != GR_NH_IPV6)
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

static void ra_init(struct event_base *base) {
	ev_base = base;
	ra_output = gr_control_input_register_handler("ip6_output", true);
	ra_ctx.mp = gr_pktmbuf_pool_get(SOCKET_ID_ANY, 512);
	if (ra_ctx.mp == NULL) {
		ABORT("gr_pktmbuf_pool_get ENOMEM");
	}
}

static void ra_fini(struct event_base * /*ev_base*/) {
	gr_pktmbuf_pool_release(ra_ctx.mp, 512);
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

static struct gr_api_handler ra_show_handler = {
	.name = "show interface ra",
	.request_type = GR_IP6_IFACE_RA_SHOW,
	.callback = iface_ra_show,
};

static void iface_event_handler(uint32_t event, const void *obj) {
	const struct iface *iface = obj;

	switch (event) {
	case GR_EVENT_IFACE_POST_ADD:
		ra_conf[iface->id].interval = RA_DEFAULT_INTERVAL;
		ra_conf[iface->id].lifetime = RA_DEFAULT_LIFETIME;
		ra_conf[iface->id].timer = event_new(
			ev_base, -1, EV_PERSIST, send_ra_cb, (void *)iface
		);
		break;
	case GR_EVENT_IFACE_PRE_REMOVE:
		event_free(ra_conf[iface->id].timer);
		ra_conf[iface->id].timer = NULL;
		break;
	}
}

static struct gr_event_subscription iface_event_sub = {
	.callback = iface_event_handler,
	.ev_count = 2,
	.ev_types = {GR_EVENT_IFACE_POST_ADD, GR_EVENT_IFACE_PRE_REMOVE},
};

RTE_INIT(router_advertisement_init) {
	gr_register_module(&ra_module);
	gr_register_api_handler(&ra_set_handler);
	gr_register_api_handler(&ra_clear_handler);
	gr_register_api_handler(&ra_show_handler);
	gr_event_subscribe(&iface_event_sub);
}
