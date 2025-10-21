// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2024 Christophe Fontaine, Red Hat
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "if_grout.h"
#include "log_grout.h"
#include "rt_grout.h"

#include <gr_api_client_impl.h>
#include <gr_srv6.h>

#include <lib/frr_pthread.h>
#include <lib/libfrr.h>
#include <zebra/zebra_dplane.h>
#include <zebra/zebra_router.h>
#include <zebra_dplane_grout.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define TOSTRING(x) #x

unsigned long zebra_debug_dplane_grout;
static const char *gr_sock_path = GR_DEFAULT_SOCK_PATH;

struct grout_ctx_t {
	struct gr_api_client *client;
	struct gr_api_client *dplane_notifs;
	struct gr_api_client *zebra_notifs;

	// Event/'thread' pointer for queued updates
	struct event *dg_t_zebra_update;
	struct event *dg_t_dplane_update;
};

static struct grout_ctx_t grout_ctx = {0};
static const char *plugin_name = "zebra_dplane_grout";

static void dplane_read_notifications(struct event *event);
static void zebra_read_notifications(struct event *event);

struct grout_evt {
	uint32_t type;
	bool suppress_self_events;
};

static int grout_notif_subscribe(
	struct gr_api_client **pgr_client,
	const struct grout_evt *gr_evts,
	unsigned int nb_gr_evts
) {
	struct gr_event_subscribe_req req;
	unsigned int i;

	*pgr_client = gr_api_client_connect(gr_sock_path);
	if (*pgr_client == NULL) {
		gr_log_err(
			"connect failed on grout sock %s error: %s", gr_sock_path, strerror(errno)
		);
		return -1;
	}

	for (i = 0; i < nb_gr_evts; i++) {
		req.suppress_self_events = gr_evts[i].suppress_self_events;
		req.ev_type = gr_evts[i].type;

		if (gr_api_client_send_recv(
			    *pgr_client, GR_MAIN_EVENT_SUBSCRIBE, sizeof(req), &req, NULL
		    )
		    < 0) {
			gr_log_err(
				"subscribe on event failed on grout sock %s error: %s",
				gr_sock_path,
				strerror(errno)
			);

			gr_api_client_disconnect(*pgr_client);
			*pgr_client = NULL;
			return -1;
		}
	}

	return 0;
}

static int grout_client_ensure_connect(void) {
	if (grout_ctx.client != NULL)
		return 0;
	grout_ctx.client = gr_api_client_connect(gr_sock_path);
	if (grout_ctx.client == NULL) {
		gr_log_err("gr_api_client_connect: %s", strerror(errno));
		return -errno;
	}
	return 0;
}

static void grout_sync_routes(struct event *e) {
	struct gr_ip4_route_list_req r4_req = {.vrf_id = EVENT_VAL(e)};
	struct gr_ip4_route *r4;
	bool link;
	int ret;

	gr_log_debug("sync routes for vrf %u", EVENT_VAL(e));

	if (grout_client_ensure_connect() < 0)
		return;

	link = true;
route4:
	gr_api_client_stream_foreach (
		r4, ret, grout_ctx.client, GR_IP4_ROUTE_LIST, sizeof(r4_req), &r4_req
	) {
		if (!link && r4->origin == GR_NH_ORIGIN_LINK)
			continue;
		if (link && r4->origin != GR_NH_ORIGIN_LINK)
			continue;
		gr_log_debug("sync route %pI4/%u", &r4->dest.ip, r4->dest.prefixlen);
		grout_route4_change(true, r4);
	}
	if (ret < 0)
		gr_log_err("GR_IP4_ROUTE_LIST: %s", strerror(errno));
	if (link) {
		link = false;
		goto route4;
	}

	struct gr_ip6_route_list_req r6_req = {.vrf_id = EVENT_VAL(e)};
	struct gr_ip6_route *r6;

	link = true;
route6:
	gr_api_client_stream_foreach (
		r6, ret, grout_ctx.client, GR_IP6_ROUTE_LIST, sizeof(r6_req), &r6_req
	) {
		if (!link && r6->origin == GR_NH_ORIGIN_LINK)
			continue;
		if (link && r6->origin != GR_NH_ORIGIN_LINK)
			continue;
		gr_log_debug("sync route %pI6/%u", &r6->dest.ip, r6->dest.prefixlen);
		grout_route6_change(true, r6);
	}
	if (ret < 0)
		gr_log_err("GR_IP6_ROUTE_LIST: %s", strerror(errno));
	if (link) {
		link = false;
		goto route6;
	}
}

static void grout_sync_nhs(struct event *e) {
	struct gr_nh_list_req nh_req = {
		.vrf_id = EVENT_VAL(e), .type = GR_NH_T_ALL, .include_internal = false
	};
	struct gr_nexthop *nh;
	int ret;

	gr_log_debug("sync nexthops for vrf %u", EVENT_VAL(e));

	if (grout_client_ensure_connect() < 0)
		return;

	gr_api_client_stream_foreach (
		nh, ret, grout_ctx.client, GR_NH_LIST, sizeof(nh_req), &nh_req
	) {
		gr_log_debug("sync nexthop %d", nh->nh_id);
		grout_nexthop_change(true, nh, true);
	}
	if (ret < 0) {
		gr_log_err("GR_NH_LIST: %s", strerror(errno));
		// No nexthop, we won't be able to add routes.
		return;
	}
	event_add_event(zrouter.master, grout_sync_routes, NULL, EVENT_VAL(e), NULL);
}

static void grout_sync_ifaces_addresses(struct event *e) {
	struct gr_ip4_addr_list_req ip_req = {
		.vrf_id = EVENT_VAL(e), .iface_id = GR_IFACE_ID_UNDEF
	};
	const struct gr_ip4_ifaddr *ip_addr;
	int ret;

	gr_log_debug("sync ifaces addresses for vrf %u", EVENT_VAL(e));

	if (grout_client_ensure_connect() < 0)
		return;

	gr_api_client_stream_foreach (
		ip_addr, ret, grout_ctx.client, GR_IP4_ADDR_LIST, sizeof(ip_req), &ip_req
	) {
		gr_log_debug("sync addr %pI4", &ip_addr->addr.ip);
		grout_interface_addr4_change(true, ip_addr);
	}
	if (ret < 0)
		gr_log_err("GR_IP4_ADDR_LIST: %s", strerror(errno));

	struct gr_ip6_addr_list_req ip6_req = {
		.vrf_id = EVENT_VAL(e), .iface_id = GR_IFACE_ID_UNDEF
	};
	const struct gr_ip6_ifaddr *ip6_addr;

	gr_api_client_stream_foreach (
		ip6_addr, ret, grout_ctx.client, GR_IP6_ADDR_LIST, sizeof(ip6_req), &ip6_req
	) {
		gr_log_debug("sync addr %pI6", &ip6_addr->addr.ip);
		grout_interface_addr6_change(true, ip6_addr);
	}
	if (ret < 0)
		gr_log_err("GR_IP6_ADDR_LIST: %s", strerror(errno));

	event_add_event(zrouter.master, grout_sync_nhs, NULL, EVENT_VAL(e), NULL);
}

static void grout_sync_ifaces(struct event *) {
	struct gr_infra_iface_list_req if_req = {.type = GR_IFACE_TYPE_UNDEF};
	bool sync_vrf[GR_MAX_VRFS] = {false};
	struct gr_iface *iface;
	int ret;

	if (grout_client_ensure_connect() < 0)
		return;

	gr_api_client_stream_foreach (
		iface, ret, grout_ctx.client, GR_INFRA_IFACE_LIST, sizeof(if_req), &if_req
	) {
		gr_log_debug("sync iface %s", iface->name);
		grout_link_change(iface, true, true);
		sync_vrf[iface->vrf_id] = true;
	}
	if (ret < 0)
		gr_log_err("GR_INFRA_IFACE_LIST: %s", strerror(errno));

	for (unsigned i = 0; i < GR_MAX_VRFS; i++) {
		if (sync_vrf[i])
			event_add_event(zrouter.master, grout_sync_ifaces_addresses, NULL, i, NULL);
	}
}

static void dplane_grout_connect(struct event *) {
	struct event_loop *dg_master = dplane_get_thread_master();
	static const struct grout_evt gr_evts[] = {
		{.type = GR_EVENT_IFACE_POST_ADD, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_STATUS_UP, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_STATUS_DOWN, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_POST_RECONFIG, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_PRE_REMOVE, .suppress_self_events = true},
		{.type = GR_EVENT_IP_ADDR_ADD, .suppress_self_events = false},
		{.type = GR_EVENT_IP6_ADDR_ADD, .suppress_self_events = false},
		{.type = GR_EVENT_IP_ADDR_DEL, .suppress_self_events = false},
		{.type = GR_EVENT_IP6_ADDR_DEL, .suppress_self_events = false},
	};

	if (grout_notif_subscribe(&grout_ctx.dplane_notifs, gr_evts, ARRAY_SIZE(gr_evts)) < 0)
		goto reschedule_connect;

	event_add_read(
		dg_master,
		dplane_read_notifications,
		NULL,
		grout_ctx.dplane_notifs->sock_fd,
		&grout_ctx.dg_t_dplane_update
	);

	gr_log_debug("monitor iface/ip events");
	return;

reschedule_connect:
	event_add_timer(dg_master, dplane_grout_connect, NULL, 1, &grout_ctx.dg_t_dplane_update);
}

static void zebra_grout_connect(struct event *) {
	static const struct grout_evt gr_evts[] = {
		{.type = GR_EVENT_IP_ROUTE_ADD, .suppress_self_events = true},
		{.type = GR_EVENT_IP_ROUTE_DEL, .suppress_self_events = true},
		{.type = GR_EVENT_NEXTHOP_NEW, .suppress_self_events = true},
		{.type = GR_EVENT_NEXTHOP_DELETE, .suppress_self_events = true},
		{.type = GR_EVENT_NEXTHOP_UPDATE, .suppress_self_events = true},
	};

	if (grout_notif_subscribe(&grout_ctx.zebra_notifs, gr_evts, ARRAY_SIZE(gr_evts)) < 0)
		goto reschedule_connect;

	event_add_read(
		zrouter.master,
		zebra_read_notifications,
		NULL,
		grout_ctx.zebra_notifs->sock_fd,
		&grout_ctx.dg_t_zebra_update
	);

	gr_log_debug("monitor route events");
	return;

reschedule_connect:
	event_add_timer(zrouter.master, zebra_grout_connect, NULL, 1, &grout_ctx.dg_t_zebra_update);
}

static const char *gr_req_type_to_str(uint32_t e) {
	switch (e) {
	case GR_IP4_ADDR_ADD:
		return TOSTRING(GR_IP4_ADDR_ADD);
	case GR_IP4_ADDR_DEL:
		return TOSTRING(GR_IP4_ADDR_DEL);
	case GR_IP6_ADDR_ADD:
		return TOSTRING(GR_IP6_ADDR_ADD);
	case GR_IP6_ADDR_DEL:
		return TOSTRING(GR_IP6_ADDR_DEL);
	case GR_IP4_ROUTE_ADD:
		return TOSTRING(GR_IP4_ROUTE_ADD);
	case GR_IP4_ROUTE_DEL:
		return TOSTRING(GR_IP4_ROUTE_DEL);
	case GR_IP6_ROUTE_ADD:
		return TOSTRING(GR_IP6_ROUTE_ADD);
	case GR_IP6_ROUTE_DEL:
		return TOSTRING(GR_IP6_ROUTE_DEL);
	case GR_NH_ADD:
		return TOSTRING(GR_NH_ADD);
	case GR_NH_DEL:
		return TOSTRING(GR_NH_DEL);
	case GR_INFRA_IFACE_LIST:
		return TOSTRING(GR_INFRA_IFACE_LIST);
	case GR_IP4_ADDR_LIST:
		return TOSTRING(GR_IP4_ADDR_LIST);
	case GR_IP6_ADDR_LIST:
		return TOSTRING(GR_IP6_ADDR_LIST);
	case GR_NH_LIST:
		return TOSTRING(GR_NH_LIST);
	case GR_IP4_ROUTE_LIST:
		return TOSTRING(GR_IP4_ROUTE_LIST);
	case GR_IP6_ROUTE_LIST:
		return TOSTRING(GR_IP6_ROUTE_LIST);
	default:
		return "unknown";
	}
}

int grout_client_send_recv(uint32_t req_type, size_t tx_len, const void *tx_data, void **rx_data) {
	bool first = true;
	int ret;

retry:
	ret = gr_api_client_send_recv(grout_ctx.client, req_type, tx_len, tx_data, rx_data);
	if (ret == 0) {
		gr_log_debug("'%s' request has success", gr_req_type_to_str(req_type));
		return 0;
	} else if (!first) {
		gr_log_err(
			"'%s' request has failed (errno=%s)",
			gr_req_type_to_str(req_type),
			strerror(errno)
		);
		return ret;
	}

	if (grout_ctx.client && errno != ECONNRESET && errno != EPIPE && errno != ENOTCONN)
		return ret;

	if (grout_ctx.client) {
		gr_api_client_disconnect(grout_ctx.client);
		grout_ctx.client = NULL;
	}

	grout_ctx.client = gr_api_client_connect(gr_sock_path);
	if (!grout_ctx.client) {
		gr_log_debug(
			"connect failed on grout sock for '%s' request",
			gr_req_type_to_str(req_type)
		);
		return -1;
	}

	first = false;
	goto retry;
}

static const char *gr_evt_to_str(uint32_t e) {
	switch (e) {
	case GR_EVENT_IFACE_POST_ADD:
		return TOSTRING(GR_EVENT_IFACE_POST_ADD);
	case GR_EVENT_IFACE_PRE_REMOVE:
		return TOSTRING(GR_EVENT_IFACE_PRE_REMOVE);
	case GR_EVENT_IFACE_STATUS_UP:
		return TOSTRING(GR_EVENT_IFACE_STATUS_UP);
	case GR_EVENT_IFACE_STATUS_DOWN:
		return TOSTRING(GR_EVENT_IFACE_STATUS_DOWN);
	case GR_EVENT_IFACE_POST_RECONFIG:
		return TOSTRING(GR_EVENT_IFACE_POST_RECONFIG);
	case GR_EVENT_IP_ADDR_ADD:
		return TOSTRING(GR_EVENT_IP_ADDR_ADD);
	case GR_EVENT_IP_ADDR_DEL:
		return TOSTRING(GR_EVENT_IP_ADDR_DEL);
	case GR_EVENT_IP6_ADDR_ADD:
		return TOSTRING(GR_EVENT_IP6_ADDR_ADD);
	case GR_EVENT_IP6_ADDR_DEL:
		return TOSTRING(GR_EVENT_IP6_ADDR_DEL);
	case GR_EVENT_IP_ROUTE_ADD:
		return TOSTRING(GR_EVENT_IP_ROUTE_ADD);
	case GR_EVENT_IP_ROUTE_DEL:
		return TOSTRING(GR_EVENT_IP_ROUTE_DEL);
	case GR_EVENT_IP6_ROUTE_ADD:
		return TOSTRING(GR_EVENT_IP6_ROUTE_ADD);
	case GR_EVENT_IP6_ROUTE_DEL:
		return TOSTRING(GR_EVENT_IP6_ROUTE_DEL);
	case GR_EVENT_NEXTHOP_NEW:
		return TOSTRING(GR_EVENT_NEXTHOP_NEW);
	case GR_EVENT_NEXTHOP_UPDATE:
		return TOSTRING(GR_EVENT_NEXTHOP_UPDATE);
	case GR_EVENT_NEXTHOP_DELETE:
		return TOSTRING(GR_EVENT_NEXTHOP_DELETE);
	default:
		return "unknown";
	}
}

static void dplane_read_notifications(struct event *event) {
	struct event_loop *dg_master = dplane_get_thread_master();
	struct gr_api_event *gr_e = NULL;
	struct gr_ip4_ifaddr *ifa4;
	struct gr_ip6_ifaddr *ifa6;
	struct gr_iface *iface;
	bool new = false;

	if (gr_api_client_event_recv(grout_ctx.dplane_notifs, &gr_e) < 0 || gr_e == NULL) {
		// On any error, reconnect
		gr_api_client_disconnect(grout_ctx.dplane_notifs);
		grout_ctx.dplane_notifs = NULL;
		event_add_timer(
			dg_master, dplane_grout_connect, NULL, 1, &grout_ctx.dg_t_dplane_update
		);
		return;
	}

	switch (gr_e->ev_type) {
	case GR_EVENT_IFACE_POST_ADD:
	case GR_EVENT_IFACE_STATUS_UP:
	case GR_EVENT_IFACE_STATUS_DOWN:
	case GR_EVENT_IFACE_POST_RECONFIG:
		new = true;
		// fallthrough
	case GR_EVENT_IFACE_PRE_REMOVE:
		iface = PAYLOAD(gr_e);

		gr_log_debug(
			"%s iface %s notification (%s)",
			new ? "add" : "del",
			iface->name,
			gr_evt_to_str(gr_e->ev_type)
		);

		grout_link_change(iface, new, false);
		break;
	case GR_EVENT_IP_ADDR_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP_ADDR_DEL:
		ifa4 = PAYLOAD(gr_e);
		gr_log_debug(
			"%s addr %pI4 notification (%s)",
			new ? "add" : "del",
			&ifa4->addr.ip,
			gr_evt_to_str(gr_e->ev_type)
		);
		grout_interface_addr4_change(new, ifa4);
		break;
	case GR_EVENT_IP6_ADDR_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP6_ADDR_DEL:
		ifa6 = PAYLOAD(gr_e);
		gr_log_debug(
			"%s addr %pI6 notification (%s)",
			new ? "add" : "del",
			&ifa6->addr.ip,
			gr_evt_to_str(gr_e->ev_type)
		);
		grout_interface_addr6_change(new, ifa6);
		break;
	default:
		gr_log_debug(
			"Unknown notification %s (0x%x) received",
			gr_evt_to_str(gr_e->ev_type),
			gr_e->ev_type
		);
		break;
	}

	free(gr_e);

	event_add_read(
		dg_master,
		dplane_read_notifications,
		NULL,
		grout_ctx.dplane_notifs->sock_fd,
		&grout_ctx.dg_t_dplane_update
	);
}

static void zebra_read_notifications(struct event *event) {
	struct gr_api_event *gr_e = NULL;
	struct gr_ip4_route *gr_r4;
	struct gr_ip6_route *gr_r6;
	struct gr_nexthop *gr_nh;
	bool new = false;

	if (gr_api_client_event_recv(grout_ctx.zebra_notifs, &gr_e) < 0 || gr_e == NULL) {
		// On any error, reconnect
		gr_api_client_disconnect(grout_ctx.zebra_notifs);
		grout_ctx.zebra_notifs = NULL;
		event_add_timer(
			zrouter.master, zebra_grout_connect, NULL, 1, &grout_ctx.dg_t_zebra_update
		);
		return;
	}

	switch (gr_e->ev_type) {
	case GR_EVENT_IP_ROUTE_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP_ROUTE_DEL:
		gr_r4 = PAYLOAD(gr_e);

		gr_log_debug(
			"%s route %pI4/%u notification (%s)",
			new ? "add" : "del",
			&gr_r4->dest.ip,
			gr_r4->dest.prefixlen,
			gr_evt_to_str(gr_e->ev_type)
		);

		grout_route4_change(new, gr_r4);
		break;
	case GR_EVENT_IP6_ROUTE_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP6_ROUTE_DEL:
		gr_r6 = PAYLOAD(gr_e);

		gr_log_debug(
			"%s route %pI6/%u notification (%s)",
			new ? "add" : "del",
			&gr_r6->dest.ip,
			gr_r6->dest.prefixlen,
			gr_evt_to_str(gr_e->ev_type)
		);

		grout_route6_change(new, gr_r6);
		break;
	case GR_EVENT_NEXTHOP_NEW:
	case GR_EVENT_NEXTHOP_UPDATE:
		new = true;
		// fallthrough
	case GR_EVENT_NEXTHOP_DELETE:
		gr_nh = PAYLOAD(gr_e);

		gr_log_debug(
			"%s nexthop %u notification (%s)",
			new ? "add" : "del",
			gr_nh->nh_id,
			gr_evt_to_str(gr_e->ev_type)
		);

		grout_nexthop_change(new, gr_nh, false);
		break;
	default:
		gr_log_debug(
			"Unknown notification %s (0x%x) received",
			gr_evt_to_str(gr_e->ev_type),
			gr_e->ev_type
		);
		break;
	}

	free(gr_e);

	event_add_read(
		zrouter.master,
		zebra_read_notifications,
		NULL,
		grout_ctx.zebra_notifs->sock_fd,
		&grout_ctx.dg_t_zebra_update
	);
}

// Grout provider callback.
static enum zebra_dplane_result zd_grout_process_update(struct zebra_dplane_ctx *ctx) {
	switch (dplane_ctx_get_op(ctx)) {
	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
		return grout_add_del_address(ctx);

	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		return grout_add_del_route(ctx);

	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
		return grout_add_del_nexthop(ctx);

	case DPLANE_OP_SRV6_ENCAP_SRCADDR_SET:
		return grout_set_sr_tunsrc(ctx);

	case DPLANE_OP_NONE:
		return ZEBRA_DPLANE_REQUEST_SUCCESS;

	default:
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
}

static int zd_grout_process(struct zebra_dplane_provider *prov) {
	struct zebra_dplane_ctx *ctx;
	enum zebra_dplane_result ret;
	int counter, limit;

	gr_log_debug("processing %s", dplane_provider_get_name(prov));

	limit = dplane_provider_get_work_limit(prov);
	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (!ctx)
			break;

		ret = zd_grout_process_update(ctx);
		dplane_ctx_set_status(ctx, ret);
		dplane_ctx_set_skip_kernel(ctx);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	return 0;
}

static void zd_grout_ns(struct event *t) {
	struct event_loop *dg_master = dplane_get_thread_master();
	struct vrf *default_vrf;

	zebra_ns_disabled(ns_get_default());

	// Delete all vrfs including the default one
	vrf_terminate();

	// Force the default main table ID to 0 (Linux uses 254)
	// Because Grout lacks tables, we reuse the vrf_id as the table ID
	// Therefore table 254 refers to vrf 254 in Grout, not to the default VRF (0)
	rt_table_main_id = 0;
	// changing id or name for default vrf is not going well in FRR
	default_vrf = vrf_get(VRF_DEFAULT, VRF_DEFAULT_NAME);
	if (!default_vrf) {
		gr_log_err("failed to recreate the default VRF!");
		exit(1);
	}
	// Enable the default VRF
	if (!vrf_enable(default_vrf)) {
		gr_log_err("failed to re-enable the default VRF!");
		exit(1);
	}

	// Add timer to connect on grout socket to get events
	event_add_timer(dg_master, dplane_grout_connect, NULL, 0, NULL);
	event_add_timer(zrouter.master, zebra_grout_connect, NULL, 0, NULL);
}

static int zd_grout_start(struct zebra_dplane_provider *prov) {
	const char *debug = getenv("ZEBRA_DEBUG_DPLANE_GROUT");
	const char *sock_path = getenv("GROUT_SOCK_PATH");

	if (vrf_is_backend_netns()) {
		gr_log_err("vrf backend netns is not supported with grout");
		exit(1); // Exit because zebra_dplane_start() does not check the return value
	}

	if (debug)
		zebra_debug_dplane_grout = (strcmp(debug, "1") == 0 || strcmp(debug, "true") == 0);
	if (sock_path)
		gr_sock_path = sock_path;

	event_add_timer(zrouter.master, zd_grout_ns, NULL, 0, NULL);

	gr_log_debug(
		"%s start (debug=%lu, gr_sock_path=%s)",
		dplane_provider_get_name(prov),
		zebra_debug_dplane_grout,
		gr_sock_path
	);

	return 0;
}

static int zd_grout_finish(struct zebra_dplane_provider *, bool early) {
	if (early) {
		event_cancel(&grout_ctx.dg_t_zebra_update);
		event_cancel_async(dplane_get_thread_master(), &grout_ctx.dg_t_dplane_update, NULL);
		return 0;
	}

	gr_api_client_disconnect(grout_ctx.client);
	gr_api_client_disconnect(grout_ctx.dplane_notifs);
	gr_api_client_disconnect(grout_ctx.zebra_notifs);
	grout_ctx.dplane_notifs = NULL;
	grout_ctx.zebra_notifs = NULL;
	grout_ctx.client = NULL;
	return 0;
}

static int zd_grout_plugin_init(struct event_loop *) {
	int ret;

	ret = dplane_provider_register(
		plugin_name,
		DPLANE_PRIO_PRE_KERNEL,
		DPLANE_PROV_FLAGS_DEFAULT,
		zd_grout_start,
		zd_grout_process,
		zd_grout_finish,
		&grout_ctx,
		NULL
	);

	if (ret != 0)
		gr_log_err("Unable to register grout dplane provider: %d", ret);

	gr_log_debug("%s register status %d", plugin_name, ret);

	return 0;
}

static int zd_grout_start_sync(struct event_loop *) {
	event_add_timer(zrouter.master, grout_sync_ifaces, NULL, 0, NULL);
	return 0;
}

static int zd_grout_module_init(void) {
	hook_register(frr_late_init, zd_grout_plugin_init);
	hook_register(frr_config_post, zd_grout_start_sync);
	return 0;
}

extern struct frrmod_runtime *frr_module; // silence -Wmissing-variable-declarations
FRR_MODULE_SETUP(
		.name = "dplane_grout",
		.version = GROUT_VERSION,
		.description = "Data plane plugin using grout",
		.init = zd_grout_module_init
);
