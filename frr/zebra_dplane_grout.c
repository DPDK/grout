// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2024 Christophe Fontaine, Red Hat
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#include <lib/queue.h>

// clang-format off
#include <gr_api_client_impl.h>
// clang-format on

#include "if_grout.h"
#include "if_map.h"
#include "log_grout.h"
#include "rt_grout.h"

#include <fcntl.h>
#include <getopt.h>
#include <lib/bitfield.h>
#include <lib/frr_pthread.h>
#include <lib/libfrr.h>
#include <lib/version.h>
#include <unistd.h>
#include <zebra/interface.h>
#include <zebra/rib.h>
#include <zebra/zebra_dplane.h>
#include <zebra/zebra_router.h>
#include <zebra/zebra_vrf.h>
#include <zebra_dplane_grout.h>

#define TOSTRING(x) #x

static const char *gr_sock_path = GR_DEFAULT_SOCK_PATH;

// Marker prefix and polling cadence. The marker is a dummy ::/128 SHARP
// entry the plugin uses as a metaQ drain barrier: once observable in
// the RIB, FIFO ordering of META_QUEUE_EARLY_ROUTE guarantees every
// earlier ere has drained.
static struct prefix grout_sync_marker_prefix = {
	.family = AF_INET6,
	.prefixlen = 128,
};
#define GROUT_SYNC_MARKER_POLL_MS 50
// One warning every ~5s while polling. No timeout: dispatch only on
// actual observation, mirroring kernel-side "Finished Initial Startup".
#define GROUT_SYNC_MARKER_WARN_EVERY 100

// Pre-arm delay for zrouter.t_rib_sweep. Only purpose: keep *t_ptr
// non-NULL so zebra_main_router_started's event_add_timer takes the
// early-return path (lib/event.c:1430) and the native sweep is a no-op.
// Value is arbitrary; the nominal path replaces this with the real arm.
#define GROUT_SYNC_SWEEP_PLACEHOLDER_SEC 3600

struct grout_ctx_t {
	struct gr_api_client *client;
	struct gr_api_client *sync_client;
	struct gr_api_client *dplane_notifs;
	struct gr_api_client *zebra_notifs;

	// Event/'thread' pointer for queued updates
	struct event *dg_t_zebra_update;
	struct event *dg_t_dplane_update;
	struct event *dg_t_sync;
	struct event *dg_t_reconnect;

	// Per-VRF sync chain event pointers
	struct event *dg_t_dplane_sync;
	struct event *dg_t_zebra_sync;
	bitfield_t sync_vrf;

	// Marker polling state. marker_cb selects the post-observation
	// action (e.g. grout_reconnect_finish). Marker is always injected
	// in VRF_DEFAULT on prefix ::/128.
	struct event *dg_t_poll_marker;
	unsigned int marker_poll_retries;
	void (*marker_cb)(void);

	// -K value cached from /proc/self/cmdline. Same semantics as FRR's
	// zebra_di.gr_cleanup_time: 0 means absent, positive means K seconds.
	int gr_cleanup_time;
};

static struct grout_ctx_t grout_ctx = {0};
static const char *plugin_name = "zebra_dplane_grout";

static void dplane_read_notifications(struct event *event);
static void zebra_read_notifications(struct event *event);
static void dplane_grout_connect(struct event *);
static void zebra_grout_connect(struct event *);
static void grout_sync(struct event *);
static void grout_sync_ifaces(struct event *);
static void grout_sync_addrs(struct event *);
static void grout_reconnect(struct event *);
static void grout_reconnect_finish(void);
static void grout_sync_arm_sweep(void);
static void grout_sync_cleanup_marker(void);
static void grout_sync_inject_marker(void);

void ipaddr_to_l3_addr(struct l3_addr *dst, const struct ipaddr *src) {
	switch (src->ipa_type) {
	case IPADDR_V4:
		dst->af = GR_AF_IP4;
		memcpy(&dst->ipv4, &src->ipaddr_v4, sizeof(dst->ipv4));
		break;
	case IPADDR_V6:
		dst->af = GR_AF_IP6;
		memcpy(&dst->ipv6, &src->ipaddr_v6, sizeof(dst->ipv6));
		break;
	default:
		dst->af = GR_AF_UNSPEC;
		break;
	}
}

void l3_addr_to_ipaddr(struct ipaddr *dst, const struct l3_addr *src) {
	switch (src->af) {
	case GR_AF_IP4:
		dst->ipa_type = IPADDR_V4;
		memcpy(&dst->ipaddr_v4, &src->ipv4, sizeof(dst->ipaddr_v4));
		break;
	case GR_AF_IP6:
		dst->ipa_type = IPADDR_V6;
		memcpy(&dst->ipaddr_v6, &src->ipv6, sizeof(dst->ipaddr_v6));
		break;
	default:
		dst->ipa_type = IPADDR_NONE;
		break;
	}
}

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

	gr_api_client_disconnect(*pgr_client);
	*pgr_client = gr_api_client_connect(gr_sock_path);
	if (*pgr_client == NULL) {
		gr_log_err("gr_api_client_connect(%s): %s", gr_sock_path, strerror(errno));
		return -1;
	}

	for (i = 0; i < nb_gr_evts; i++) {
		req.suppress_self_events = gr_evts[i].suppress_self_events;
		req.ev_type = gr_evts[i].type;

		if (gr_api_client_send_recv(
			    *pgr_client, GR_EVENT_SUBSCRIBE, sizeof(req), &req, NULL
		    )
		    < 0) {
			gr_log_err("gr_api_client_send_recv: %s", strerror(errno));

			gr_api_client_disconnect(*pgr_client);
			*pgr_client = NULL;
			return -1;
		}
	}

	return 0;
}

static void grout_sync_fdb(struct event *) {
	struct gr_fdb_list_req req = {.bridge_id = GR_IFACE_ID_UNDEF};
	struct gr_fdb_entry *fdb;
	int ret;

	gr_log_debug("sync FDB entries");

	gr_api_client_stream_foreach (fdb, ret, grout_ctx.client, GR_FDB_LIST, sizeof(req), &req) {
		gr_log_debug(
			"sync fdb bridge %u iface %u mac %pEA",
			fdb->bridge_id,
			fdb->iface_id,
			&fdb->mac
		);
		grout_macfdb_change(fdb, true);
	}
	if (ret < 0)
		gr_log_err("GR_FDB_LIST: %s", strerror(errno));

	// Start per-VRF sync chain with the first VRF
	for (unsigned int i = 0; i < GR_MAX_IFACES; i++) {
		if (bf_test_index(grout_ctx.sync_vrf, i)) {
			event_add_event(
				dplane_get_thread_master(),
				grout_sync_addrs,
				NULL,
				i,
				&grout_ctx.dg_t_dplane_sync
			);
			return;
		}
	}
}

// Recover -K by re-parsing /proc/self/cmdline. zebra_di.gr_cleanup_time
// is static in main.c (not exported) and zrouter.t_rib_sweep loses the
// value after firing. Returns the -K seconds, or 0 if absent (matches
// FRR's libfrr.c default + atoi semantics). Called once from
// zd_grout_plugin_init (single-threaded, before event loop).
static int grout_read_k_from_cmdline(void) {
	// 1 MiB cap; ARG_MAX is 2 MiB, MTYPE_TMP aborts on OOM.
	const size_t buf_cap_max = 1024 * 1024;
	char *buf = NULL, **argv = NULL;
	size_t buf_cap = 4096, buf_len = 0;
	int argc = 0, argv_cap = 0;
	int fd, ret = 0;

	fd = open("/proc/self/cmdline", O_RDONLY);
	if (fd < 0) {
		gr_log_warn("/proc/self/cmdline: %s", strerror(errno));
		return 0;
	}

	buf = XMALLOC(MTYPE_TMP, buf_cap);

	for (;;) {
		ssize_t n = read(fd, buf + buf_len, buf_cap - buf_len - 1);
		if (n < 0)
			goto out;
		if (n == 0)
			break;
		buf_len += n;
		if (buf_len >= buf_cap - 1) {
			if (buf_cap >= buf_cap_max) {
				gr_log_warn(
					"/proc/self/cmdline exceeds %zu bytes, truncating; "
					"-K parsing may miss the flag",
					buf_cap_max
				);
				goto out;
			}
			buf_cap *= 2;
			if (buf_cap > buf_cap_max)
				buf_cap = buf_cap_max;
			buf = XREALLOC(MTYPE_TMP, buf, buf_cap);
		}
	}
	if (buf_len == 0)
		goto out;
	buf[buf_len] = '\0';

	for (size_t i = 0; i < buf_len; i++)
		if (buf[i] == '\0')
			argv_cap++;

	argv = XCALLOC(MTYPE_TMP, (argv_cap + 1) * sizeof(*argv));
	for (char *p = buf; p < buf + buf_len; p += strlen(p) + 1)
		argv[argc++] = p;
	argv[argc] = NULL;

	static const struct option lo[] = {
		{"graceful_restart", optional_argument, NULL, 'K'}, {0, 0, 0, 0}
	};
	int saved_optind = optind;
	int saved_opterr = opterr;
	optind = 1;
	opterr = 0;
	int c;
	while ((c = getopt_long(argc, argv, ":K::", lo, NULL)) != -1) {
		if (c == 'K' && optarg)
			ret = atoi(optarg);
	}
	optind = saved_optind;
	opterr = saved_opterr;

out:
	close(fd);
	XFREE(MTYPE_TMP, argv);
	XFREE(MTYPE_TMP, buf);
	return ret;
}

// Run the post-observation action set up by the marker injector.
static void grout_sync_dispatch_marker_cb(void) {
	void (*cb)(void) = grout_ctx.marker_cb;
	grout_ctx.marker_cb = NULL;
	assert(cb);
	cb();
}

// Arm rib_sweep_route after observing the end-of-replay marker.
// Re-stamp zrouter.startup_time to "now" so -K is measured from the
// end of the grout dump (mirrors Donald Sharp's "Delay some processing
// until after startup is finished"). Replaces the pre-arm placeholder
// installed by zd_grout_plugin_init.
static void grout_sync_arm_sweep(void) {
	grout_sync_cleanup_marker();

	time_t old_startup_time = zrouter.startup_time;
	zrouter.startup_time = monotime(NULL);
	gr_log_debug(
		"restamping zrouter.startup_time %lld -> %lld; -K window starts now",
		(long long)old_startup_time,
		(long long)zrouter.startup_time
	);

	long delay = 0;
	if (zrouter.graceful_restart) {
		// Truthy check matches zebra/main.c: 0 falls back to default.
		delay = grout_ctx.gr_cleanup_time ?
			grout_ctx.gr_cleanup_time :
			ZEBRA_GR_DEFAULT_RIB_SWEEP_TIME;
	}
	event_cancel(&zrouter.t_rib_sweep);
	event_add_timer(zrouter.master, rib_sweep_route, NULL, delay, &zrouter.t_rib_sweep);
}

// Poll the RIB for our marker. FIFO ordering of META_QUEUE_EARLY_ROUTE
// guarantees that when the marker is observable, every earlier ere has
// been attached. The marker itself is skipped by rib_process (distance
// INFINITY + type != KERNEL): never selected, never installed.
static void grout_sync_poll_marker(struct event *e) {
	struct route_table *table;
	struct route_node *rn;
	struct route_entry *re;
	bool found = false;

	// !table: keep polling, do not dispatch. The marker is a strict
	// FIFO barrier; a best-effort dispatch would defeat its purpose.
	table = zebra_vrf_table(AFI_IP6, SAFI_UNICAST, VRF_DEFAULT);
	if (table) {
		rn = route_node_lookup(table, &grout_sync_marker_prefix);
		if (rn) {
			RNODE_FOREACH_RE(rn, re) {
				if (CHECK_FLAG(re->status, ROUTE_ENTRY_REMOVED))
					continue;
				if (re->tag == GROUT_SYNC_MARKER_TAG
				    && re->type == ZEBRA_ROUTE_SHARP) {
					found = true;
					break;
				}
			}
			route_unlock_node(rn);
		}
	}

	if (found) {
		gr_log_info(
			"sync marker observed after %u poll(s) (%u ms)",
			grout_ctx.marker_poll_retries + 1,
			(grout_ctx.marker_poll_retries + 1) * GROUT_SYNC_MARKER_POLL_MS
		);
		goto dispatch;
	}

	grout_ctx.marker_poll_retries++;
	if (grout_ctx.marker_poll_retries % GROUT_SYNC_MARKER_WARN_EVERY == 0) {
		gr_log_warn(
			"sync marker still not visible after %u ms; metaQ drain may be slow",
			grout_ctx.marker_poll_retries * GROUT_SYNC_MARKER_POLL_MS
		);
	}

	event_add_timer_msec(
		zrouter.master,
		grout_sync_poll_marker,
		NULL,
		GROUT_SYNC_MARKER_POLL_MS,
		&grout_ctx.dg_t_poll_marker
	);
	return;

dispatch:
	grout_sync_dispatch_marker_cb();
}

// Drop the marker route (in metaQ or already attached). Idempotent:
// the FRR APIs are no-op if no matching entry exists, so this is safe
// to call before injecting a new marker (covers an interrupted
// previous reconnect) or after observation (cosmetic cleanup).
static void grout_sync_cleanup_marker(void) {
#if CURRENT_FRR_VERSION >= MAKE_FRRVERSION(10, 6, 0)
	rib_meta_queue_early_route_cleanup(
		&grout_sync_marker_prefix, AFI_IP6, SAFI_UNICAST, VRF_DEFAULT, ZEBRA_ROUTE_SHARP
	);
#else
	rib_meta_queue_early_route_cleanup(&grout_sync_marker_prefix, ZEBRA_ROUTE_SHARP);
#endif
	rib_delete(
		AFI_IP6,
		SAFI_UNICAST,
		VRF_DEFAULT,
		ZEBRA_ROUTE_SHARP,
		0,
		0,
		&grout_sync_marker_prefix,
		NULL,
		NULL,
		0,
		0,
		0,
		0,
		false
	);
}

// Inject the marker into VRF_DEFAULT and kick off polling.
//   prefix     ::/128         never a real destination
//   type       SHARP          test/demo, no collision
//   distance   INFINITY (255) rib_process skips it
//   flags      0              keeps it out of rib_sweep_table predicate
//   tag        unique id      distinguishes from user routes on ::/128
//   nexthop    blackhole      inert (entry never installed)
static void grout_sync_inject_marker(void) {
	// Local non-const copy: rib_add_multipath takes a non-const prefix
	// pointer and may apply_mask in-place.
	struct prefix p = grout_sync_marker_prefix;
	struct nexthop *nh;
	struct nexthop_group *ng;
	struct route_entry *re;

	nh = nexthop_new();
	nh->type = NEXTHOP_TYPE_BLACKHOLE;
	nh->bh_type = BLACKHOLE_NULL;
	nh->vrf_id = VRF_DEFAULT;

	ng = nexthop_group_new();
	nexthop_group_add_sorted(ng, nh);

	re = zebra_rib_route_entry_new(
		VRF_DEFAULT,
		ZEBRA_ROUTE_SHARP,
		0,
		0,
		0,
		0,
		0,
		0,
		DISTANCE_INFINITY,
		GROUT_SYNC_MARKER_TAG
	);

	grout_ctx.marker_poll_retries = 0;

#if CURRENT_FRR_VERSION >= MAKE_FRRVERSION(10, 6, 0)
	rib_add_multipath(AFI_IP6, SAFI_UNICAST, &p, NULL, re, ng, true, false);
#else
	rib_add_multipath(AFI_IP6, SAFI_UNICAST, &p, NULL, re, ng, true);
#endif

	nexthop_group_delete(&ng);

	event_add_timer_msec(
		zrouter.master,
		grout_sync_poll_marker,
		NULL,
		GROUT_SYNC_MARKER_POLL_MS,
		&grout_ctx.dg_t_poll_marker
	);
}

static void grout_sync_routes(struct event *e) {
	struct gr_ip4_route_list_req r4_req = {.vrf_id = EVENT_VAL(e), .max_count = 0};
	struct gr_ip4_route *r4;
	bool link;
	int ret;

	gr_log_info("vrf %u", EVENT_VAL(e));

	link = true;
route4:
	gr_api_client_stream_foreach (
		r4, ret, grout_ctx.sync_client, GR_IP4_ROUTE_LIST, sizeof(r4_req), &r4_req
	) {
		if (!link && r4->origin == GR_NH_ORIGIN_LINK)
			continue;
		if (link && r4->origin != GR_NH_ORIGIN_LINK)
			continue;
		grout_route4_change(true, r4, true);
	}
	if (ret < 0) {
		gr_log_err("GR_IP4_ROUTE_LIST: %s", strerror(errno));
		goto err;
	}
	if (link) {
		link = false;
		goto route4;
	}

	struct gr_ip6_route_list_req r6_req = {.vrf_id = EVENT_VAL(e), .max_count = 0};
	struct gr_ip6_route *r6;

	link = true;
route6:
	gr_api_client_stream_foreach (
		r6, ret, grout_ctx.sync_client, GR_IP6_ROUTE_LIST, sizeof(r6_req), &r6_req
	) {
		if (!link && r6->origin == GR_NH_ORIGIN_LINK)
			continue;
		if (link && r6->origin != GR_NH_ORIGIN_LINK)
			continue;
		grout_route6_change(true, r6, true);
	}
	if (ret < 0) {
		gr_log_err("GR_IP6_ROUTE_LIST: %s", strerror(errno));
		goto err;
	}
	if (link) {
		link = false;
		goto route6;
	}

	// Pass 3: chain to routes of next VRF. NHEs from all VRFs are
	// already registered (Pass 2 ran nhs for every VRF before any
	// routes), so cross-VRF NH references resolve at inject time.
	for (unsigned int i = EVENT_VAL(e) + 1; i < GR_MAX_IFACES; i++) {
		if (bf_test_index(grout_ctx.sync_vrf, i)) {
			event_add_event(
				zrouter.master,
				grout_sync_routes,
				NULL,
				i,
				&grout_ctx.dg_t_zebra_sync
			);
			return;
		}
	}

	// All VRFs synced. Defer arming rib_sweep_route until the marker is
	// observed: arming inline would race the metaQ drain and miss
	// not-yet-attached SELFROUTE injections.
	grout_ctx.marker_cb = grout_sync_arm_sweep;
	grout_sync_inject_marker();
	return;

err:
	event_add_timer(zrouter.master, grout_reconnect, NULL, 1, &grout_ctx.dg_t_zebra_sync);
}

static void grout_sync_nhs(struct event *e) {
	struct gr_nh_list_req nh_req = {
		.vrf_id = EVENT_VAL(e), .type = GR_NH_T_ALL, .include_internal = false
	};
	struct gr_nexthop *nh;
	int ret;

	gr_log_info("vrf %u", EVENT_VAL(e));

	gr_api_client_stream_foreach (
		nh, ret, grout_ctx.sync_client, GR_NH_LIST, sizeof(nh_req), &nh_req
	) {
		grout_nexthop_change(true, nh, true);
	}
	if (ret < 0) {
		gr_log_err("GR_NH_LIST: %s", strerror(errno));
		event_add_timer(
			zrouter.master, grout_reconnect, NULL, 1, &grout_ctx.dg_t_zebra_sync
		);
		return;
	}

	// Pass 2 (this VRF done): chain to nhs of next VRF.
	// All NHs across all VRFs are registered before any route is
	// injected so cross-VRF NH references (e.g. SR6_LOCAL with
	// out_vrf in a different VRF than the prefix being matched)
	// resolve at route inject time.
	for (unsigned int i = EVENT_VAL(e) + 1; i < GR_MAX_IFACES; i++) {
		if (bf_test_index(grout_ctx.sync_vrf, i)) {
			event_add_event(
				zrouter.master, grout_sync_nhs, NULL, i, &grout_ctx.dg_t_zebra_sync
			);
			return;
		}
	}

	// Pass 2 done across all VRFs. Kick off Pass 3 (routes) starting
	// from the first VRF.
	for (unsigned int i = 0; i < GR_MAX_IFACES; i++) {
		if (bf_test_index(grout_ctx.sync_vrf, i)) {
			event_add_event(
				zrouter.master,
				grout_sync_routes,
				NULL,
				i,
				&grout_ctx.dg_t_zebra_sync
			);
			return;
		}
	}
}

static void grout_sync_addrs(struct event *e) {
	struct gr_ip4_addr_list_req ip_req = {
		.vrf_id = EVENT_VAL(e), .iface_id = GR_IFACE_ID_UNDEF
	};
	const struct gr_ip4_ifaddr *ip_addr;
	int ret;

	gr_log_info("vrf %u", EVENT_VAL(e));

	gr_api_client_stream_foreach (
		ip_addr, ret, grout_ctx.sync_client, GR_IP4_ADDR_LIST, sizeof(ip_req), &ip_req
	) {
		grout_interface_addr4_change(true, ip_addr);
	}
	if (ret < 0) {
		gr_log_err("GR_IP4_ADDR_LIST: %s", strerror(errno));
		goto err;
	}

	struct gr_ip6_addr_list_req ip6_req = {
		.vrf_id = EVENT_VAL(e), .iface_id = GR_IFACE_ID_UNDEF
	};
	const struct gr_ip6_ifaddr *ip6_addr;

	gr_api_client_stream_foreach (
		ip6_addr, ret, grout_ctx.sync_client, GR_IP6_ADDR_LIST, sizeof(ip6_req), &ip6_req
	) {
		grout_interface_addr6_change(true, ip6_addr);
	}
	if (ret < 0) {
		gr_log_err("GR_IP6_ADDR_LIST: %s", strerror(errno));
		goto err;
	}

	// Pass 1 (this VRF done): chain to addrs of next VRF.
	// All addrs across all VRFs are processed before any nhs, mirroring
	// the kernel dplane init order (links -> addrs -> nexthops -> routes).
	for (unsigned int i = EVENT_VAL(e) + 1; i < GR_MAX_IFACES; i++) {
		if (bf_test_index(grout_ctx.sync_vrf, i)) {
			event_add_event(
				dplane_get_thread_master(),
				grout_sync_addrs,
				NULL,
				i,
				&grout_ctx.dg_t_dplane_sync
			);
			return;
		}
	}

	// Pass 1 done across all VRFs. Kick off Pass 2 (nhs) starting
	// from the first VRF.
	for (unsigned int i = 0; i < GR_MAX_IFACES; i++) {
		if (bf_test_index(grout_ctx.sync_vrf, i)) {
			event_add_event(
				zrouter.master, grout_sync_nhs, NULL, i, &grout_ctx.dg_t_zebra_sync
			);
			return;
		}
	}
	return;

err:
	event_add_timer(zrouter.master, grout_reconnect, NULL, 1, &grout_ctx.dg_t_zebra_sync);
}

static void grout_sync(struct event *) {
	gr_api_client_disconnect(grout_ctx.sync_client);
	grout_ctx.sync_client = gr_api_client_connect(gr_sock_path);
	if (grout_ctx.sync_client == NULL) {
		gr_log_info("waiting for grout at %s: %s", gr_sock_path, strerror(errno));
		event_add_timer(zrouter.master, grout_sync, NULL, 1, &grout_ctx.dg_t_sync);
		return;
	}

	// grout is available, schedule notification channels and sync
	event_add_timer(dplane_get_thread_master(), dplane_grout_connect, NULL, 0, NULL);
	event_add_timer(zrouter.master, zebra_grout_connect, NULL, 0, NULL);
	event_add_event(
		dplane_get_thread_master(), grout_sync_ifaces, NULL, 0, &grout_ctx.dg_t_dplane_sync
	);
}

static void grout_sync_ifaces(struct event *) {
	// Sync interfaces in dependency order.
	static const gr_iface_type_t types[] = {
		GR_IFACE_TYPE_VRF, // no dependencies
		GR_IFACE_TYPE_BRIDGE, // needs VRF domain
		GR_IFACE_TYPE_IPIP, // needs VRF domain
		GR_IFACE_TYPE_VXLAN, // needs bridge domain and encap VRF
		GR_IFACE_TYPE_BOND, // needs VRF/bridge domain
		GR_IFACE_TYPE_PORT, // needs bond/VRF/bridge domain
		GR_IFACE_TYPE_VLAN, // needs parent port/bond and VRF/bridge domain
	};
	struct gr_iface_list_req if_req;
	struct gr_iface *iface;
	unsigned int i;
	int ret;

	memset(grout_ctx.sync_vrf.data, 0, grout_ctx.sync_vrf.m * sizeof(word_t));
	grout_ctx.sync_vrf.n = 0;

	for (i = 0; i < ARRAY_DIM(types); i++) {
		if_req.type = types[i];

		gr_api_client_stream_foreach (
			iface, ret, grout_ctx.sync_client, GR_IFACE_LIST, sizeof(if_req), &if_req
		) {
			grout_link_change(iface, true, true);
			bf_set_bit(grout_ctx.sync_vrf, iface->vrf_id);
		}

		if (ret < 0) {
			gr_log_err(
				"GR_IFACE_LIST(%s): %s",
				gr_iface_type_name(types[i]),
				strerror(errno)
			);
			goto err;
		}
	}

	event_add_event(zrouter.master, grout_sync_fdb, NULL, 0, &grout_ctx.dg_t_zebra_sync);
	return;

err:
	event_add_timer(zrouter.master, grout_reconnect, NULL, 1, &grout_ctx.dg_t_zebra_sync);
}

static void dplane_grout_connect(struct event *) {
	struct event_loop *dg_master = dplane_get_thread_master();
	static const struct grout_evt gr_evts[] = {
		{.type = GR_EVENT_IFACE_ADD, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_STATUS_UP, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_STATUS_DOWN, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_POST_RECONFIG, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_MAC_CHANGE, .suppress_self_events = true},
		{.type = GR_EVENT_IFACE_REMOVE, .suppress_self_events = true},
		{.type = GR_EVENT_IP_ADDR_ADD, .suppress_self_events = false},
		{.type = GR_EVENT_IP6_ADDR_ADD, .suppress_self_events = false},
		{.type = GR_EVENT_IP_ADDR_DEL, .suppress_self_events = false},
		{.type = GR_EVENT_IP6_ADDR_DEL, .suppress_self_events = false},
		{.type = GR_EVENT_FDB_ADD, .suppress_self_events = true},
		{.type = GR_EVENT_FDB_DEL, .suppress_self_events = true},
		{.type = GR_EVENT_FDB_UPDATE, .suppress_self_events = true},
	};

	gr_api_client_disconnect(grout_ctx.client);
	grout_ctx.client = gr_api_client_connect(gr_sock_path);
	if (grout_ctx.client == NULL) {
		gr_log_err("gr_api_client_connect: %s", strerror(errno));
		event_add_timer(
			zrouter.master, grout_reconnect, NULL, 1, &grout_ctx.dg_t_reconnect
		);
		return;
	}

	if (grout_notif_subscribe(&grout_ctx.dplane_notifs, gr_evts, ARRAY_DIM(gr_evts)) < 0) {
		gr_api_client_disconnect(grout_ctx.client);
		grout_ctx.client = NULL;
		event_add_timer(
			zrouter.master, grout_reconnect, NULL, 1, &grout_ctx.dg_t_reconnect
		);
		return;
	}

	event_add_read(
		dg_master,
		dplane_read_notifications,
		NULL,
		grout_ctx.dplane_notifs->sock_fd,
		&grout_ctx.dg_t_dplane_update
	);

	gr_log_notice("connected, monitoring iface/ip events");
}

static void zebra_grout_connect(struct event *) {
	static const struct grout_evt gr_evts[] = {
		{.type = GR_EVENT_IP_ROUTE_ADD, .suppress_self_events = true},
		{.type = GR_EVENT_IP_ROUTE_DEL, .suppress_self_events = true},
		{.type = GR_EVENT_IP6_ROUTE_ADD, .suppress_self_events = true},
		{.type = GR_EVENT_IP6_ROUTE_DEL, .suppress_self_events = true},
		{.type = GR_EVENT_NEXTHOP_NEW, .suppress_self_events = true},
		{.type = GR_EVENT_NEXTHOP_DELETE, .suppress_self_events = true},
		{.type = GR_EVENT_NEXTHOP_UPDATE, .suppress_self_events = true},
	};

	if (grout_notif_subscribe(&grout_ctx.zebra_notifs, gr_evts, ARRAY_DIM(gr_evts)) < 0) {
		event_add_timer(
			zrouter.master, grout_reconnect, NULL, 1, &grout_ctx.dg_t_reconnect
		);
		return;
	}

	event_add_read(
		zrouter.master,
		zebra_read_notifications,
		NULL,
		grout_ctx.zebra_notifs->sock_fd,
		&grout_ctx.dg_t_zebra_update
	);

	gr_log_notice("connected, monitoring route/nexthop events");
}

int grout_client_send_recv(uint32_t req_type, size_t tx_len, const void *tx_data, void **rx_data) {
	int ret;

	if (grout_ctx.client == NULL)
		return errno_set(ENOTCONN);

	ret = gr_api_client_send_recv(grout_ctx.client, req_type, tx_len, tx_data, rx_data);
	if (ret == 0) {
		gr_log_debug("%s: success", gr_api_message_name(req_type));
		return 0;
	}

	gr_log_err("%s: %s", gr_api_message_name(req_type), strerror(errno));

	if (errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN) {
		gr_api_client_disconnect(grout_ctx.client);
		grout_ctx.client = NULL;
		event_add_timer(
			zrouter.master, grout_reconnect, NULL, 1, &grout_ctx.dg_t_reconnect
		);
	}

	return ret;
}

static void dplane_read_notifications(struct event *event) {
	struct event_loop *dg_master = dplane_get_thread_master();
	struct gr_api_event *gr_e = NULL;
	bool new = false;

	if (gr_api_client_event_recv(grout_ctx.dplane_notifs, &gr_e) < 0 || gr_e == NULL) {
		gr_api_client_disconnect(grout_ctx.dplane_notifs);
		grout_ctx.dplane_notifs = NULL;
		gr_api_client_disconnect(grout_ctx.client);
		grout_ctx.client = NULL;
		event_add_timer(
			zrouter.master, grout_reconnect, NULL, 1, &grout_ctx.dg_t_reconnect
		);
		return;
	}

	gr_log_debug("%s", gr_api_message_name(gr_e->ev_type));

	switch (gr_e->ev_type) {
	case GR_EVENT_IFACE_ADD:
	case GR_EVENT_IFACE_STATUS_UP:
	case GR_EVENT_IFACE_STATUS_DOWN:
	case GR_EVENT_IFACE_POST_RECONFIG:
	case GR_EVENT_IFACE_MAC_CHANGE:
		new = true;
		// fallthrough
	case GR_EVENT_IFACE_REMOVE:
		grout_link_change(PAYLOAD(gr_e), new, false);
		break;
	case GR_EVENT_IP_ADDR_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP_ADDR_DEL:
		grout_interface_addr4_change(new, PAYLOAD(gr_e));
		break;
	case GR_EVENT_IP6_ADDR_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP6_ADDR_DEL:
		grout_interface_addr6_change(new, PAYLOAD(gr_e));
		break;

	case GR_EVENT_FDB_ADD:
	case GR_EVENT_FDB_UPDATE:
		new = true;
		// fallthrough
	case GR_EVENT_FDB_DEL:
		grout_macfdb_change(PAYLOAD(gr_e), new);
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
	bool new = false;

	if (gr_api_client_event_recv(grout_ctx.zebra_notifs, &gr_e) < 0 || gr_e == NULL) {
		gr_api_client_disconnect(grout_ctx.zebra_notifs);
		grout_ctx.zebra_notifs = NULL;
		event_add_timer(
			zrouter.master, grout_reconnect, NULL, 1, &grout_ctx.dg_t_reconnect
		);
		return;
	}

	gr_log_debug("%s", gr_api_message_name(gr_e->ev_type));

	switch (gr_e->ev_type) {
	case GR_EVENT_IP_ROUTE_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP_ROUTE_DEL:
		grout_route4_change(new, PAYLOAD(gr_e), false);
		break;
	case GR_EVENT_IP6_ROUTE_ADD:
		new = true;
		// fallthrough
	case GR_EVENT_IP6_ROUTE_DEL:
		grout_route6_change(new, PAYLOAD(gr_e), false);
		break;
	case GR_EVENT_NEXTHOP_NEW:
	case GR_EVENT_NEXTHOP_UPDATE:
		new = true;
		// fallthrough
	case GR_EVENT_NEXTHOP_DELETE:
		grout_nexthop_change(new, PAYLOAD(gr_e), false);
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

	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
		return grout_macfdb_update_ctx(ctx);

	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
		return grout_vxlan_flood_update_ctx(ctx);

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

static void grout_ns_reset(void) {
	struct vrf *default_vrf, *vrf;
	struct interface *ifp;

	RB_FOREACH(vrf, vrf_id_head, &vrfs_by_id) {
		FOR_ALL_INTERFACES(vrf, ifp) {
			if_down(ifp);
		}
	}

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
}

// Phase 2 of grout_reconnect: barrier observed, metaQ drained, safe to
// wipe and re-sync. vrf_terminate clears OLD ere's attached to OLD VRF.
static void grout_reconnect_finish(void) {
	grout_ns_reset();
	event_add_event(zrouter.master, grout_sync, NULL, 0, &grout_ctx.dg_t_sync);
}

static void grout_reconnect(struct event *) {
	gr_log_notice("grout disconnected, performing full re-sync");

	event_cancel(&grout_ctx.dg_t_zebra_update);
	event_cancel(&grout_ctx.dg_t_zebra_sync);
	event_cancel(&grout_ctx.dg_t_reconnect);
	event_cancel(&grout_ctx.dg_t_sync);
	event_cancel(&grout_ctx.dg_t_poll_marker);
	event_cancel_async(dplane_get_thread_master(), &grout_ctx.dg_t_dplane_update, NULL);
	event_cancel_async(dplane_get_thread_master(), &grout_ctx.dg_t_dplane_sync, NULL);

	// Drop any marker left over from an interrupted prior reconnect
	// before injecting the new barrier.
	grout_sync_cleanup_marker();

	gr_api_client_disconnect(grout_ctx.sync_client);
	grout_ctx.sync_client = NULL;
	clear_ifindex_mappings();

	// Inject a barrier marker before destroying VRF_DEFAULT. FIFO drain
	// guarantees all earlier ere's are attached when observed; vrf_terminate
	// (in grout_reconnect_finish) then wipes them along with the VRF.
	grout_ctx.marker_cb = grout_reconnect_finish;
	grout_sync_inject_marker();
}

static void zd_grout_ns(struct event *) {
	struct event_loop *dg_master = dplane_get_thread_master();

	// zebra_ns_disabled() calls event_cancel_async() on the dplane event
	// loop which asserts that the caller is not its owner. At startup, the
	// dplane event loop owner is still the main thread until the dplane
	// pthread has actually started and claimed it. Retry until it has.
#if CURRENT_FRR_VERSION >= MAKE_FRRVERSION(10, 6, 0)
	if (frr_event_loop_get_pthread_owner(dg_master) == pthread_self()) {
#else
	if (dg_master->owner == pthread_self()) {
#endif
		event_add_timer_msec(zrouter.master, zd_grout_ns, NULL, 10, NULL);
		return;
	}

	grout_ns_reset();
}

static int zd_grout_start(struct zebra_dplane_provider *prov) {
	const char *sock_path = getenv("GROUT_SOCK_PATH");

	if (vrf_is_backend_netns()) {
		gr_log_err("vrf backend netns is not supported with grout");
		exit(1); // Exit because zebra_dplane_start() does not check the return value
	}

	if (sock_path)
		gr_sock_path = sock_path;

	event_add_timer(zrouter.master, zd_grout_ns, NULL, 0, NULL);

	gr_log_debug("%s start sock_path=%s", dplane_provider_get_name(prov), gr_sock_path);

	return 0;
}

static int zd_grout_finish(struct zebra_dplane_provider *, bool early) {
	if (early) {
		event_cancel(&grout_ctx.dg_t_zebra_update);
		event_cancel(&grout_ctx.dg_t_zebra_sync);
		event_cancel(&grout_ctx.dg_t_reconnect);
		event_cancel(&grout_ctx.dg_t_sync);
		event_cancel(&grout_ctx.dg_t_poll_marker);
		event_cancel_async(dplane_get_thread_master(), &grout_ctx.dg_t_dplane_update, NULL);
		event_cancel_async(dplane_get_thread_master(), &grout_ctx.dg_t_dplane_sync, NULL);
		return 0;
	}

	bf_free(grout_ctx.sync_vrf);

	gr_api_client_disconnect(grout_ctx.client);
	gr_api_client_disconnect(grout_ctx.sync_client);
	gr_api_client_disconnect(grout_ctx.dplane_notifs);
	gr_api_client_disconnect(grout_ctx.zebra_notifs);
	grout_ctx.client = NULL;
	grout_ctx.sync_client = NULL;
	grout_ctx.dplane_notifs = NULL;
	grout_ctx.zebra_notifs = NULL;
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

	// Cache -K once: single-threaded under frr_late_init.
	grout_ctx.gr_cleanup_time = grout_read_k_from_cmdline();

	// Pre-arm to neutralise the native sweep: zebra_main_router_started's
	// event_add_timer(... &zrouter.t_rib_sweep) early-returns when the
	// pointer is non-NULL (lib/event.c:1430).
	event_add_timer(
		zrouter.master,
		rib_sweep_route,
		NULL,
		GROUT_SYNC_SWEEP_PLACEHOLDER_SEC,
		&zrouter.t_rib_sweep
	);

	// Detect FRR drift: if pre-arm did not set the pointer, the native
	// sweep will fire uncontrolled. Plugin still works (predicate skips
	// dump entries by uptime), just noisy.
	if (!zrouter.t_rib_sweep)
		gr_log_err("pre-arm failed: FRR event API may have changed");

	return 0;
}

static int zd_grout_start_sync(struct event_loop *) {
	event_add_timer(zrouter.master, grout_sync, NULL, 0, &grout_ctx.dg_t_sync);
	return 0;
}

static int zd_grout_module_init(void) {
	const char *runtime_version = frr_defaults_version();
	unsigned build_maj, build_min, build_patch;
	unsigned run_maj, run_min, run_patch;

	if (sscanf(FRR_VER_SHORT, "%u.%u.%u", &build_maj, &build_min, &build_patch) != 3
	    || sscanf(runtime_version, "%u.%u.%u", &run_maj, &run_min, &run_patch) != 3) {
		gr_log_err(
			"failed to parse FRR version: build=%s runtime=%s",
			FRR_VER_SHORT,
			runtime_version
		);
		return -1;
	}
	if (build_maj != run_maj || build_min != run_min) {
		gr_log_err(
			"FRR version mismatch: plugin built for %s but running %s",
			FRR_VER_SHORT,
			runtime_version
		);
		return -1;
	}
	if (build_patch != run_patch) {
		gr_log_warn("plugin built for FRR %s, running %s.", FRR_VER_SHORT, runtime_version);
	}

	hook_register(frr_late_init, zd_grout_plugin_init);
	hook_register(frr_config_post, zd_grout_start_sync);
	init_ifindex_mappings();
	bf_init(grout_ctx.sync_vrf, GR_MAX_IFACES);
	return 0;
}

extern struct frrmod_runtime *frr_module; // silence -Wmissing-variable-declarations
FRR_MODULE_SETUP(
		.name = "dplane_grout",
		.version = GROUT_VERSION,
		.description = "Data plane plugin using grout",
		.init = zd_grout_module_init
);
