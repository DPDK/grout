// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_infra.h>
#include <gr_ip4.h>
#include <gr_ip6.h>
#include <gr_net_types.h>

static cmd_status_t events_show(const struct gr_api_client *c, const struct ec_pnode *) {
	struct gr_event_subscribe_req req = {
		.suppress_self_events = false, .ev_type = EVENT_TYPE_ALL
	};
	struct gr_infra_iface_get_resp *p;
	struct gr_api_event *e = NULL;
	struct gr_ip4_route *r4;
	struct gr_ip6_route *r6;
	struct gr_nexthop *nh;

	if (gr_api_client_send_recv(c, GR_MAIN_EVENT_SUBSCRIBE, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	while (gr_api_client_event_recv(c, &e) == 0) {
		switch (e->ev_type) {
		case GR_EVENT_IFACE_POST_ADD:
			assert(e->payload_len == sizeof(*p));
			p = PAYLOAD(e);
			printf("> iface add: %s\n", p->iface.name);
			break;
		case GR_EVENT_IFACE_PRE_REMOVE:
			assert(e->payload_len == sizeof(*p));
			p = PAYLOAD(e);
			printf("> iface del: %s\n", p->iface.name);
			break;
		case GR_EVENT_IFACE_STATUS_UP:
			assert(e->payload_len == sizeof(*p));
			p = PAYLOAD(e);
			printf("> iface up: %s\n", p->iface.name);
			break;
		case GR_EVENT_IFACE_STATUS_DOWN:
			assert(e->payload_len == sizeof(*p));
			p = PAYLOAD(e);
			printf("> iface down: %s\n", p->iface.name);
			break;
		case GR_EVENT_IFACE_POST_RECONFIG:
			assert(e->payload_len == sizeof(*p));
			p = PAYLOAD(e);
			printf("> iface reconf: %s\n", p->iface.name);
			break;
		case GR_EVENT_IP_ADDR_ADD:
		case GR_EVENT_IP6_ADDR_ADD:
			assert(e->payload_len == sizeof(*nh));
			nh = PAYLOAD(e);
			printf("> addr add: iface[%d] " ADDR_F "\n",
			       nh->iface_id,
			       ADDR_W(nh->af),
			       &nh->addr);
			break;
		case GR_EVENT_IP_ADDR_DEL:
		case GR_EVENT_IP6_ADDR_DEL:
			assert(e->payload_len == sizeof(*nh));
			nh = PAYLOAD(e);
			printf("> addr del: iface[%d] " ADDR_F "\n",
			       nh->iface_id,
			       ADDR_W(nh->af),
			       &nh->addr);
			break;
		case GR_EVENT_IP_ROUTE_ADD:
			assert(e->payload_len == sizeof(*r4));
			r4 = PAYLOAD(e);
			printf("> route add: %4p/%d via %4p origin %s\n",
			       &r4->dest.ip,
			       r4->dest.prefixlen,
			       &r4->nh.ipv4,
			       gr_nh_origin_name(r4->origin));
			break;
		case GR_EVENT_IP_ROUTE_DEL:
			assert(e->payload_len == sizeof(*r4));
			r4 = PAYLOAD(e);
			printf("> route del: %4p/%d via %4p origin %s\n",
			       &r4->dest.ip,
			       r4->dest.prefixlen,
			       &r4->nh.ipv4,
			       gr_nh_origin_name(r4->origin));
			break;
		case GR_EVENT_IP6_ROUTE_ADD:
			assert(e->payload_len == sizeof(*r6));
			r6 = PAYLOAD(e);
			printf("> route add: %6p/%d via %6p origin %s\n",
			       &r6->dest.ip,
			       r6->dest.prefixlen,
			       &r6->nh.ipv6,
			       gr_nh_origin_name(r6->origin));
			break;
		case GR_EVENT_IP6_ROUTE_DEL:
			assert(e->payload_len == sizeof(*r6));
			r6 = PAYLOAD(e);
			printf("> route del: %6p/%d via %6p origin %s\n",
			       &r6->dest.ip,
			       r6->dest.prefixlen,
			       &r6->nh.ipv6,
			       gr_nh_origin_name(r6->origin));
			break;
		case GR_EVENT_NEXTHOP_NEW:
			assert(e->payload_len == sizeof(*nh));
			nh = PAYLOAD(e);
			printf("> nh new: iface %d vrf %d " ADDR_F " " ETH_F " origin %s\n",
			       nh->iface_id,
			       nh->vrf_id,
			       ADDR_W(nh->af),
			       &nh->addr,
			       &nh->mac,
			       gr_nh_origin_name(nh->origin));
			break;
		case GR_EVENT_NEXTHOP_DELETE:
			assert(e->payload_len == sizeof(*nh));
			nh = PAYLOAD(e);
			printf("> nh del: iface %d vrf %d " ADDR_F " " ETH_F "  origin %s\n",
			       nh->iface_id,
			       nh->vrf_id,
			       ADDR_W(nh->af),
			       &nh->addr,
			       &nh->mac,
			       gr_nh_origin_name(nh->origin));
			break;
		case GR_EVENT_NEXTHOP_UPDATE:
			assert(e->payload_len == sizeof(*nh));
			nh = PAYLOAD(e);
			printf("> nh update: iface %d vrf %d " ADDR_F " " ETH_F " origin %s\n",
			       nh->iface_id,
			       nh->vrf_id,
			       ADDR_W(nh->af),
			       &nh->addr,
			       &nh->mac,
			       gr_nh_origin_name(nh->origin));
			break;
		default:
			printf("> unknown event 0x%08x\n", e->ev_type);
			break;
		}
		free(e);
	}

	gr_api_client_send_recv(c, GR_MAIN_EVENT_UNSUBSCRIBE, 0, NULL, NULL);

	return 0;
}

static int ctx_init(struct ec_node *root) {
	return CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW),
		"events",
		events_show,
		"Subscribe to all events and dump them in real time"
	);
}

static struct gr_cli_context ctx = {
	.name = "events",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
