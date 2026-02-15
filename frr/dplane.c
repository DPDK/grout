// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2024 Christophe Fontaine, Red Hat
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include "dplane.h"
#include "iface.h"
#include "ifmap.h"
#include "log.h"
#include "nh.h"
#include "route.h"

#include <gr_api_client_impl.h>
#include <gr_srv6.h>

#include <lib/frr_pthread.h>
#include <lib/libfrr.h>
#include <zebra/zebra_dplane.h>
#include <zebra/zebra_router.h>

static const char *zg_sock_path = GR_DEFAULT_SOCK_PATH;

struct zg_ctx_t {
	struct gr_api_client *client;
	struct gr_api_client *dplane_notifs;
	struct gr_api_client *zebra_notifs;

	// Event/'thread' pointer for queued updates
	struct event *dg_t_zebra_update;
	struct event *dg_t_dplane_update;
};

static struct zg_ctx_t zg_ctx = {0};
static const char *zg_plugin_name = "zebra_dplane_grout";

static void zg_dplane_event_process(struct event *event);
static void zg_zebra_event_process(struct event *event);

struct zg_event {
	uint32_t type;
	bool suppress_self_events;
};

static int
zg_subscribe(struct gr_api_client **client, const struct zg_event *events, unsigned int n_events) {
	struct gr_event_subscribe_req req;
	unsigned int i;

	*client = gr_api_client_connect(zg_sock_path);
	if (*client == NULL) {
		zg_log_err("gr_api_client_connect: %s", strerror(errno));
		return -1;
	}

	for (i = 0; i < n_events; i++) {
		req.suppress_self_events = events[i].suppress_self_events;
		req.ev_type = events[i].type;

		if (gr_api_client_send_recv(
			    *client, GR_MAIN_EVENT_SUBSCRIBE, sizeof(req), &req, NULL
		    )
		    < 0) {
			zg_log_err("subscription failed: %s", strerror(errno));

			gr_api_client_disconnect(*client);
			*client = NULL;
			return -1;
		}
	}

	return 0;
}

static int zg_ensure_connect(void) {
	if (zg_ctx.client != NULL)
		return 0;
	zg_ctx.client = gr_api_client_connect(zg_sock_path);
	if (zg_ctx.client == NULL) {
		zg_log_err("gr_api_client_connect: %s", strerror(errno));
		return -errno;
	}
	return 0;
}

static void zg_route_sync_in(struct event *e) {
	struct gr_ip4_route_list_req r4_req = {.vrf_id = EVENT_VAL(e)};
	struct gr_ip4_route *r4;
	bool link;
	int ret;

	zg_log_notice("vrf %u", EVENT_VAL(e));

	if (zg_ensure_connect() < 0)
		return;

	link = true;
route4:
	gr_api_client_stream_foreach (
		r4, ret, zg_ctx.client, GR_IP4_ROUTE_LIST, sizeof(r4_req), &r4_req
	) {
		if (!link && r4->origin == GR_NH_ORIGIN_LINK)
			continue;
		if (link && r4->origin != GR_NH_ORIGIN_LINK)
			continue;
		zg_route4_in(true, r4);
	}
	if (ret < 0)
		zg_log_err("GR_IP4_ROUTE_LIST: %s", strerror(errno));
	if (link) {
		link = false;
		goto route4;
	}

	struct gr_ip6_route_list_req r6_req = {.vrf_id = EVENT_VAL(e)};
	struct gr_ip6_route *r6;

	link = true;
route6:
	gr_api_client_stream_foreach (
		r6, ret, zg_ctx.client, GR_IP6_ROUTE_LIST, sizeof(r6_req), &r6_req
	) {
		if (!link && r6->origin == GR_NH_ORIGIN_LINK)
			continue;
		if (link && r6->origin != GR_NH_ORIGIN_LINK)
			continue;
		zg_route6_in(true, r6);
	}
	if (ret < 0)
		zg_log_err("GR_IP6_ROUTE_LIST: %s", strerror(errno));
	if (link) {
		link = false;
		goto route6;
	}
}

static void zg_nh_sync_in(struct event *e) {
	struct gr_nh_list_req nh_req = {
		.vrf_id = EVENT_VAL(e), .type = GR_NH_T_ALL, .include_internal = false
	};
	struct gr_nexthop *nh;
	int ret;

	zg_log_notice("vrf %u", EVENT_VAL(e));

	if (zg_ensure_connect() < 0)
		return;

	gr_api_client_stream_foreach (nh, ret, zg_ctx.client, GR_NH_LIST, sizeof(nh_req), &nh_req) {
		zg_nh_in(true, nh, true);
	}
	if (ret < 0) {
		zg_log_err("GR_NH_LIST: %s", strerror(errno));
		return;
	}
	event_add_event(zrouter.master, zg_route_sync_in, NULL, EVENT_VAL(e), NULL);
}

static void zg_addr_sync_in(struct event *e) {
	struct gr_ip4_addr_list_req ip_req = {
		.vrf_id = EVENT_VAL(e), .iface_id = GR_IFACE_ID_UNDEF
	};
	const struct gr_ip4_ifaddr *addr4;
	int ret;

	zg_log_notice("vrf %u", EVENT_VAL(e));

	if (zg_ensure_connect() < 0)
		return;

	gr_api_client_stream_foreach (
		addr4, ret, zg_ctx.client, GR_IP4_ADDR_LIST, sizeof(ip_req), &ip_req
	) {
		zg_iface_addr4_in(true, addr4);
	}
	if (ret < 0)
		zg_log_err("GR_IP4_ADDR_LIST: %s", strerror(errno));

	struct gr_ip6_addr_list_req ip6_req = {
		.vrf_id = EVENT_VAL(e), .iface_id = GR_IFACE_ID_UNDEF
	};
	const struct gr_ip6_ifaddr *addr6;

	gr_api_client_stream_foreach (
		addr6, ret, zg_ctx.client, GR_IP6_ADDR_LIST, sizeof(ip6_req), &ip6_req
	) {
		zg_iface_addr6_in(true, addr6);
	}
	if (ret < 0)
		zg_log_err("GR_IP6_ADDR_LIST: %s", strerror(errno));

	event_add_event(zrouter.master, zg_nh_sync_in, NULL, EVENT_VAL(e), NULL);
}

static void zg_iface_sync_in(struct event *) {
	static const gr_iface_type_t types[] = {
		GR_IFACE_TYPE_VRF,
		GR_IFACE_TYPE_BOND,
		GR_IFACE_TYPE_IPIP,
		GR_IFACE_TYPE_PORT,
		GR_IFACE_TYPE_VLAN,
	};
	struct gr_infra_iface_list_req if_req;
	bool sync_vrf[GR_MAX_IFACES] = {false};
	struct gr_iface *iface;
	unsigned int i;
	int ret;

	if (zg_ensure_connect() < 0)
		return;

	for (i = 0; i < ARRAY_DIM(types); i++) {
		if_req.type = types[i];

		gr_api_client_stream_foreach (
			iface, ret, zg_ctx.client, GR_INFRA_IFACE_LIST, sizeof(if_req), &if_req
		) {
			zg_iface_in(iface, true, true);
			sync_vrf[iface->vrf_id] = true;
		}

		if (ret < 0)
			zg_log_err(
				"GR_INFRA_IFACE_LIST(%s): %s",
				gr_iface_type_name(types[i]),
				strerror(errno)
			);
	}

	for (i = 0; i < GR_MAX_IFACES; i++) {
		if (sync_vrf[i])
			event_add_event(zrouter.master, zg_addr_sync_in, NULL, i, NULL);
	}
}

static void zg_dplane_connect(struct event *) {
	struct event_loop *dg_master = dplane_get_thread_master();
	static const struct zg_event events[] = {
		{.type = GR_EVENT_IFACE_ADD, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_STATUS_UP, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_STATUS_DOWN, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_POST_RECONFIG, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_REMOVE, .suppress_self_events = true},
		{.type = GR_EVENT_IP_ADDR_ADD, .suppress_self_events = false},
		{.type = GR_EVENT_IP6_ADDR_ADD, .suppress_self_events = false},
		{.type = GR_EVENT_IP_ADDR_DEL, .suppress_self_events = false},
		{.type = GR_EVENT_IP6_ADDR_DEL, .suppress_self_events = false},
	};

	if (zg_subscribe(&zg_ctx.dplane_notifs, events, ARRAY_DIM(events)) < 0)
		goto reschedule_connect;

	event_add_read(
		dg_master,
		zg_dplane_event_process,
		NULL,
		zg_ctx.dplane_notifs->sock_fd,
		&zg_ctx.dg_t_dplane_update
	);

	zg_log_notice("connected, monitoring iface/ip events");
	return;

reschedule_connect:
	event_add_timer(dg_master, zg_dplane_connect, NULL, 1, &zg_ctx.dg_t_dplane_update);
}

static void zg_zebra_connect(struct event *) {
	static const struct zg_event events[] = {
		{.type = GR_EVENT_IP_ROUTE_ADD, .suppress_self_events = true},
		{.type = GR_EVENT_IP_ROUTE_DEL, .suppress_self_events = true},
		{.type = GR_EVENT_NEXTHOP_NEW, .suppress_self_events = true},
		{.type = GR_EVENT_NEXTHOP_DELETE, .suppress_self_events = true},
		{.type = GR_EVENT_NEXTHOP_UPDATE, .suppress_self_events = true},
	};

	if (zg_subscribe(&zg_ctx.zebra_notifs, events, ARRAY_DIM(events)) < 0)
		goto reschedule_connect;

	event_add_read(
		zrouter.master,
		zg_zebra_event_process,
		NULL,
		zg_ctx.zebra_notifs->sock_fd,
		&zg_ctx.dg_t_zebra_update
	);

	zg_log_notice("connected, monitoring route/nh events");
	return;

reschedule_connect:
	event_add_timer(zrouter.master, zg_zebra_connect, NULL, 1, &zg_ctx.dg_t_zebra_update);
}

int zg_send_recv(uint32_t req_type, size_t tx_len, const void *tx_data, void **rx_data) {
	bool first = true;
	int ret;

retry:
	ret = gr_api_client_send_recv(zg_ctx.client, req_type, tx_len, tx_data, rx_data);
	if (ret == 0) {
		return 0;
	} else if (!first) {
		zg_log_err("gr_api_client_send_recv: %s", strerror(errno));
		return ret;
	}

	if (zg_ctx.client && errno != ECONNRESET && errno != EPIPE && errno != ENOTCONN)
		return ret;

	if (zg_ctx.client) {
		gr_api_client_disconnect(zg_ctx.client);
		zg_ctx.client = NULL;
	}

	zg_ctx.client = gr_api_client_connect(zg_sock_path);
	if (!zg_ctx.client) {
		zg_log_debug("gr_api_client_connect: %s", strerror(errno));
		return -1;
	}

	first = false;
	goto retry;
}

static void zg_dplane_event_process(struct event *event) {
	struct event_loop *dg_master = dplane_get_thread_master();
	struct gr_api_event *ev = NULL;
	struct gr_ip4_ifaddr *ifa4;
	struct gr_ip6_ifaddr *ifa6;
	struct gr_iface *iface;
	bool new = false;

	if (gr_api_client_event_recv(zg_ctx.dplane_notifs, &ev) < 0 || ev == NULL) {
		gr_api_client_disconnect(zg_ctx.dplane_notifs);
		zg_ctx.dplane_notifs = NULL;
		event_add_timer(dg_master, zg_dplane_connect, NULL, 1, &zg_ctx.dg_t_dplane_update);
		return;
	}

	switch (ev->ev_type) {
	case GR_EVENT_IFACE_ADD:
	case GR_EVENT_IFACE_STATUS_UP:
	case GR_EVENT_IFACE_STATUS_DOWN:
	case GR_EVENT_IFACE_POST_RECONFIG:
		new = true;
		// fallthrough
	case GR_EVENT_IFACE_REMOVE:
		iface = PAYLOAD(ev);
		zg_iface_in(iface, new, false);
		break;
	case GR_EVENT_IP_ADDR_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP_ADDR_DEL:
		ifa4 = PAYLOAD(ev);
		zg_iface_addr4_in(new, ifa4);
		break;
	case GR_EVENT_IP6_ADDR_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP6_ADDR_DEL:
		ifa6 = PAYLOAD(ev);
		zg_iface_addr6_in(new, ifa6);
		break;
	default:
		zg_log_err("unknown event 0x%x", ev->ev_type);
		break;
	}

	free(ev);

	event_add_read(
		dg_master,
		zg_dplane_event_process,
		NULL,
		zg_ctx.dplane_notifs->sock_fd,
		&zg_ctx.dg_t_dplane_update
	);
}

static void zg_zebra_event_process(struct event *event) {
	struct gr_api_event *ev = NULL;
	struct gr_ip4_route *r4;
	struct gr_ip6_route *r6;
	struct gr_nexthop *nh;
	bool new = false;

	if (gr_api_client_event_recv(zg_ctx.zebra_notifs, &ev) < 0 || ev == NULL) {
		gr_api_client_disconnect(zg_ctx.zebra_notifs);
		zg_ctx.zebra_notifs = NULL;
		event_add_timer(
			zrouter.master, zg_zebra_connect, NULL, 1, &zg_ctx.dg_t_zebra_update
		);
		return;
	}

	switch (ev->ev_type) {
	case GR_EVENT_IP_ROUTE_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP_ROUTE_DEL:
		r4 = PAYLOAD(ev);
		zg_route4_in(new, r4);
		break;
	case GR_EVENT_IP6_ROUTE_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP6_ROUTE_DEL:
		r6 = PAYLOAD(ev);
		zg_route6_in(new, r6);
		break;
	case GR_EVENT_NEXTHOP_NEW:
	case GR_EVENT_NEXTHOP_UPDATE:
		new = true;
		// fallthrough
	case GR_EVENT_NEXTHOP_DELETE:
		nh = PAYLOAD(ev);
		zg_nh_in(new, nh, false);
		break;
	default:
		zg_log_err("unknown event 0x%x", ev->ev_type);
		break;
	}

	free(ev);

	event_add_read(
		zrouter.master,
		zg_zebra_event_process,
		NULL,
		zg_ctx.zebra_notifs->sock_fd,
		&zg_ctx.dg_t_zebra_update
	);
}

static enum zebra_dplane_result zg_dplane_dispatch(struct zebra_dplane_ctx *ctx) {
	switch (dplane_ctx_get_op(ctx)) {
	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
		return zg_addr_out(ctx);

	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		return zg_route_out(ctx);

	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
		return zg_nh_out(ctx);

	case DPLANE_OP_SRV6_ENCAP_SRCADDR_SET:
		return zg_srv6_tunsrc_out(ctx);

	case DPLANE_OP_NONE:
		return ZEBRA_DPLANE_REQUEST_SUCCESS;

	default:
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
}

static int zg_dplane_dequeue(struct zebra_dplane_provider *prov) {
	struct zebra_dplane_ctx *ctx;
	enum zebra_dplane_result ret;
	int counter, limit;

	limit = dplane_provider_get_work_limit(prov);
	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (!ctx)
			break;

		ret = zg_dplane_dispatch(ctx);
		dplane_ctx_set_status(ctx, ret);
		dplane_ctx_set_skip_kernel(ctx);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	return 0;
}

static void zg_ns_init(struct event *t) {
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
		zg_log_err("failed to recreate the default VRF!");
		exit(1);
	}
	// Enable the default VRF
	if (!vrf_enable(default_vrf)) {
		zg_log_err("failed to re-enable the default VRF!");
		exit(1);
	}

	// Add timer to connect on grout socket to get events
	event_add_timer(dg_master, zg_dplane_connect, NULL, 0, NULL);
	event_add_timer(zrouter.master, zg_zebra_connect, NULL, 0, NULL);
}

static int zg_start(struct zebra_dplane_provider *prov) {
	const char *sock_path = getenv("GROUT_SOCK_PATH");

	if (vrf_is_backend_netns()) {
		zg_log_err("vrf backend netns is not supported with grout");
		exit(1);
	}

	if (sock_path)
		zg_sock_path = sock_path;

	event_add_timer(zrouter.master, zg_ns_init, NULL, 0, NULL);

	zg_log_notice("%s started (sock_path=%s)", dplane_provider_get_name(prov), zg_sock_path);

	return 0;
}

static int zg_finish(struct zebra_dplane_provider *, bool early) {
	if (early) {
		event_cancel(&zg_ctx.dg_t_zebra_update);
		event_cancel_async(dplane_get_thread_master(), &zg_ctx.dg_t_dplane_update, NULL);
		return 0;
	}

	gr_api_client_disconnect(zg_ctx.client);
	gr_api_client_disconnect(zg_ctx.dplane_notifs);
	gr_api_client_disconnect(zg_ctx.zebra_notifs);
	zg_ctx.dplane_notifs = NULL;
	zg_ctx.zebra_notifs = NULL;
	zg_ctx.client = NULL;
	return 0;
}

static int zg_plugin_init(struct event_loop *) {
	int ret;

	ret = dplane_provider_register(
		zg_plugin_name,
		DPLANE_PRIO_PRE_KERNEL,
		DPLANE_PROV_FLAGS_DEFAULT,
		zg_start,
		zg_dplane_dequeue,
		zg_finish,
		&zg_ctx,
		NULL
	);

	if (ret != 0)
		zg_log_err("unable to register grout dplane provider: %d", ret);

	return 0;
}

static int zg_start_sync(struct event_loop *) {
	event_add_timer(zrouter.master, zg_iface_sync_in, NULL, 0, NULL);
	return 0;
}

static int zg_module_init(void) {
	hook_register(frr_late_init, zg_plugin_init);
	hook_register(frr_config_post, zg_start_sync);
	zg_ifmap_init();
	return 0;
}

extern struct frrmod_runtime *frr_module; // silence -Wmissing-variable-declarations
FRR_MODULE_SETUP(
		.name = "dplane_grout",
		.version = GROUT_VERSION,
		.description = "Data plane plugin using grout",
		.init = zg_module_init
);
