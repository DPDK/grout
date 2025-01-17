// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_infra.h>
#include <gr_ip4.h>
#include <gr_ip6.h>
#include <gr_net_types.h>

#include <pthread.h>
#include <signal.h>

static cmd_status_t notifications_dump(const struct gr_api_client *c, const struct ec_pnode *) {
	struct gr_infra_iface_get_resp *p;
	struct gr_api_notification *n;
	struct gr_ip4_route *r4;
	struct gr_ip6_route *r6;
	struct gr_nexthop *nh;

	if (gr_api_client_enable_notifications(c) < 0)
		return CMD_ERROR;

	while (gr_api_client_recv_notification(c, &n) == 0) {
		switch (n->type) {
		case IFACE_EVENT_POST_ADD:
			assert(n->payload_len == sizeof(*p));
			p = PAYLOAD(n);
			printf("Iface added: %s\n", p->iface.name);
			break;
		case IFACE_EVENT_PRE_REMOVE:
			assert(n->payload_len == sizeof(*p));
			p = PAYLOAD(n);
			printf("Iface deleted: %s\n", p->iface.name);
			break;
		case IFACE_EVENT_STATUS_UP:
			assert(n->payload_len == sizeof(*p));
			p = PAYLOAD(n);
			printf("Iface status UP: %s\n", p->iface.name);
			break;
		case IFACE_EVENT_STATUS_DOWN:
			assert(n->payload_len == sizeof(*p));
			p = PAYLOAD(n);
			printf("Iface status DOWN: %s\n", p->iface.name);
			break;
		case IFACE_EVENT_POST_RECONFIG:
			assert(n->payload_len == sizeof(*p));
			p = PAYLOAD(n);
			printf("Iface reconfigured: %s\n", p->iface.name);
			break;
		case IP_EVENT_ADDR_ADD:
		case IP6_EVENT_ADDR_ADD:
			assert(n->payload_len == sizeof(*nh));
			nh = PAYLOAD(n);
			printf("IP address add: iface[%d] " ADDR_F "\n",
			       nh->iface_id,
			       ADDR_W(nh->family),
			       &nh->addr);
			break;
		case IP_EVENT_ADDR_DEL:
		case IP6_EVENT_ADDR_DEL:
			assert(n->payload_len == sizeof(*nh));
			nh = PAYLOAD(n);
			printf("IP address del: iface[%d] " ADDR_F "\n",
			       nh->iface_id,
			       ADDR_W(nh->family),
			       &nh->addr);
			break;
		case IP_EVENT_ROUTE_ADD:
			assert(n->payload_len == sizeof(*r4));
			r4 = PAYLOAD(n);
			printf("IP route add: %4p/%d via %4p\n",
			       &r4->dest.ip,
			       r4->dest.prefixlen,
			       &r4->nh);
			break;
		case IP_EVENT_ROUTE_DEL:
			assert(n->payload_len == sizeof(*r4));
			r4 = PAYLOAD(n);
			printf("IP route del: %4p/%d via %4p\n",
			       &r4->dest.ip,
			       r4->dest.prefixlen,
			       &r4->nh);
			break;
		case IP6_EVENT_ROUTE_ADD:
			assert(n->payload_len == sizeof(*r6));
			r6 = PAYLOAD(n);
			printf("IP route add: %6p/%d via %6p\n",
			       &r6->dest.ip,
			       r6->dest.prefixlen,
			       &r6->nh);
			break;
		case IP6_EVENT_ROUTE_DEL:
			assert(n->payload_len == sizeof(*r6));
			r6 = PAYLOAD(n);
			printf("IP route del: %6p/%d via %6p\n",
			       &r6->dest.ip,
			       r6->dest.prefixlen,
			       &r6->nh);
			break;
		default:
			printf("Unknown notification 0x%x received\n", n->type);
			break;
		}
		free(n);
	}

	gr_api_client_disable_notifications(c);
	return 0;
}

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW),
		"notifications",
		notifications_dump,
		"Display all notifications"
	);

	if (ret < 0)
		return ret;

	return 0;
}

static struct gr_cli_context ctx = {
	.name = "notifications",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
