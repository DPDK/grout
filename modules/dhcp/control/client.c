// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#include "client.h"

#include <gr_api.h>
#include <gr_control_input.h>
#include <gr_control_queue.h>
#include <gr_dhcp.h>
#include <gr_iface.h>
#include <gr_ip4_control.h>
#include <gr_log.h>
#include <gr_mempool.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>
#include <gr_nh_control.h>

#include <event2/event.h>
#include <rte_mbuf.h>
#include <rte_random.h>

#include <errno.h>
#include <stdlib.h>
#include <time.h>

static struct event_base *dhcp_ev_base;
static struct dhcp_client *dhcp_clients[MAX_IFACES];
static control_input_t dhcp_output;
static struct rte_mempool *dhcp_mp;

bool dhcp_enabled(uint16_t iface_id) {
	if (iface_id < MAX_IFACES)
		return dhcp_clients[iface_id] != NULL;
	return false;
}

static int dhcp_configure_interface(struct dhcp_client *client) {
	const struct iface *iface;
	int ret;

	iface = iface_from_id(client->iface_id);
	if (iface == NULL)
		return -errno;

	if (client->prefixlen == 0) {
		LOG(ERR, "server did not provide subnet mask, rejecting offer");
		return errno_set(EINVAL);
	}

	ret = addr4_add(client->iface_id, client->offered_ip, client->prefixlen, GR_NH_ORIGIN_DHCP);
	if (ret < 0) {
		LOG(ERR, "failed to configure address: %s", strerror(errno));
		return ret;
	}

	LOG(INFO,
	    "configured address " IP4_F "/%hhu on iface %s",
	    &client->offered_ip,
	    client->prefixlen,
	    iface->name);

	// Add default route if router option was provided
	if (client->router_ip != 0) {
		struct nexthop *nh = nh4_lookup(iface->vrf_id, client->router_ip);
		bool created = false;

		if (nh == NULL) {
			struct gr_nexthop_base base = {
				.type = GR_NH_T_L3,
				.origin = GR_NH_ORIGIN_DHCP,
				.iface_id = iface->id,
				.vrf_id = iface->vrf_id,
			};
			struct gr_nexthop_info_l3 l3 = {
				.af = GR_AF_IP4,
				.ipv4 = client->router_ip,
				.prefixlen = 0,
				.flags = GR_NH_F_GATEWAY,
			};
			if ((nh = nexthop_new(&base, &l3)) == NULL) {
				LOG(WARNING,
				    "failed to create gateway nexthop: %s",
				    strerror(errno));
				return 0; // Continue even if gateway creation fails
			}
			created = true;
		}

		ret = rib4_insert(iface->vrf_id, 0, 0, GR_NH_ORIGIN_DHCP, nh);
		if (ret < 0) {
			if (created)
				nexthop_decref(nh);
			LOG(WARNING, "failed to add default route: %s", strerror(-ret));
		} else {
			LOG(INFO, "added default route via " IP4_F, &client->router_ip);
		}
	}

	return 0;
}

static int dhcp_send_request(struct dhcp_client *client) {
	struct rte_mbuf *m;

	m = dhcp_build_request(
		client->iface_id, client->xid, client->server_ip, client->offered_ip
	);
	if (m == NULL)
		return -errno;

	if (post_to_stack(dhcp_output, m) < 0) {
		rte_pktmbuf_free(m);
		return -errno;
	}

	LOG(INFO, "iface=%u state=%s", client->iface_id, gr_dhcp_state_name(client->state));

	return 0;
}

static int dhcp_send_discover(struct dhcp_client *client) {
	struct rte_mbuf *m;

	m = dhcp_build_discover(client->iface_id, client->xid);
	if (m == NULL)
		return -errno;

	if (post_to_stack(dhcp_output, m) < 0) {
		rte_pktmbuf_free(m);
		return -errno;
	}

	LOG(INFO, "iface=%u state=%s", client->iface_id, gr_dhcp_state_name(client->state));

	return 0;
}

static void dhcp_cancel_timers(struct dhcp_client *client) {
	if (client->t1_timer != NULL) {
		event_free(client->t1_timer);
		client->t1_timer = NULL;
	}
	if (client->t2_timer != NULL) {
		event_free(client->t2_timer);
		client->t2_timer = NULL;
	}
	if (client->expire_timer != NULL) {
		event_free(client->expire_timer);
		client->expire_timer = NULL;
	}
}

static void dhcp_t1_callback(evutil_socket_t, short, void *arg) {
	struct dhcp_client *client = arg;

	if (client->state != DHCP_STATE_BOUND) {
		LOG(WARNING,
		    "T1 timer fired but not in BOUND state (state=%s)",
		    gr_dhcp_state_name(client->state));
		return;
	}

	LOG(INFO, "T1 timer expired, transitioning to RENEWING (iface=%u)", client->iface_id);
	client->state = DHCP_STATE_RENEWING;

	if (dhcp_send_request(client) < 0)
		LOG(ERR, "dhcp_send_request: %s", strerror(errno));
}

static void dhcp_t2_callback(evutil_socket_t, short, void *arg) {
	struct dhcp_client *client = arg;

	if (client->state != DHCP_STATE_RENEWING) {
		LOG(WARNING,
		    "T2 timer fired but not in RENEWING state (state=%s)",
		    gr_dhcp_state_name(client->state));
		return;
	}

	LOG(INFO, "T2 timer expired, transitioning to REBINDING (iface=%u)", client->iface_id);
	client->state = DHCP_STATE_REBINDING;

	if (dhcp_send_request(client) < 0)
		LOG(ERR, "dhcp_send_request: %s", strerror(errno));
}

static void dhcp_expire_callback(evutil_socket_t, short, void *arg) {
	struct dhcp_client *client = arg;
	const struct iface *iface;

	LOG(WARNING, "lease expired on iface %u", client->iface_id);

	iface = iface_from_id(client->iface_id);
	if (iface == NULL)
		return;

	if (client->offered_ip != 0 && client->prefixlen != 0)
		addr4_delete(iface->id, client->offered_ip, client->prefixlen);
	if (client->router_ip != 0)
		rib4_delete(iface->vrf_id, 0, 0, GR_NH_T_L3);

	client->state = DHCP_STATE_INIT;
	client->offered_ip = 0;
	client->server_ip = 0;
	client->prefixlen = 0;
	client->router_ip = 0;
	client->xid = rte_rand();

	if (dhcp_send_discover(client) < 0) {
		LOG(ERR, "dhcp_send_discover: %s", strerror(errno));
		return;
	}

	client->state = DHCP_STATE_SELECTING;
	LOG(INFO, "lease expired, sent new DISCOVER (iface=%u)", client->iface_id);
}

static void dhcp_schedule_timers(struct dhcp_client *client) {
	struct timeval t1_tv, t2_tv, expire_tv;
	uint32_t t1_secs, t2_secs;

	dhcp_cancel_timers(client);

	client->lease_start = time(NULL);

	if (client->renewal_time == 0)
		t1_secs = client->lease_time / 2; // 50% of lease
	else
		t1_secs = client->renewal_time;

	if (client->rebind_time == 0)
		t2_secs = (client->lease_time * 7) / 8; // 87.5% of lease
	else
		t2_secs = client->rebind_time;

	t1_tv.tv_sec = t1_secs;
	t1_tv.tv_usec = 0;
	client->t1_timer = evtimer_new(dhcp_ev_base, dhcp_t1_callback, client);
	if (client->t1_timer != NULL) {
		evtimer_add(client->t1_timer, &t1_tv);
	} else {
		LOG(WARNING, "failed to create T1 timer");
	}

	t2_tv.tv_sec = t2_secs;
	t2_tv.tv_usec = 0;
	client->t2_timer = evtimer_new(dhcp_ev_base, dhcp_t2_callback, client);
	if (client->t2_timer != NULL) {
		evtimer_add(client->t2_timer, &t2_tv);
	} else {
		LOG(WARNING, "failed to create T2 timer");
	}

	expire_tv.tv_sec = client->lease_time;
	expire_tv.tv_usec = 0;
	client->expire_timer = evtimer_new(dhcp_ev_base, dhcp_expire_callback, client);
	if (client->expire_timer != NULL) {
		evtimer_add(client->expire_timer, &expire_tv);
	} else {
		LOG(WARNING, "failed to create expire timer");
	}

	LOG(INFO,
	    "scheduled timers T1=%us, T2=%us, expire=%us (iface=%u)",
	    t1_secs,
	    t2_secs,
	    client->lease_time,
	    client->iface_id);
}

void dhcp_input_cb(void *obj, uintptr_t, const struct control_queue_drain *drain) {
	struct rte_mbuf *mbuf = obj;
	const struct iface *iface = mbuf_data(mbuf)->iface;
	dhcp_message_type_t msg_type = 0;
	struct dhcp_client *client;

	// Check if packet references deleted interface.
	if (drain != NULL && drain->event == GR_EVENT_IFACE_REMOVE && iface == drain->obj)
		goto free;

	if (iface == NULL)
		goto free;

	client = dhcp_clients[iface->id];
	if (client == NULL) {
		LOG(DEBUG, "no DHCP client on iface %s, ignoring", iface->name);
		goto free;
	}

	if (dhcp_parse_packet(mbuf, client, &msg_type) < 0)
		goto free;

	switch (client->state) {
	case DHCP_STATE_SELECTING:
		if (msg_type == DHCP_OFFER) {
			if (client->server_ip == 0 || client->offered_ip == 0) {
				LOG(ERR, "invalid OFFER (no server IP or offered IP)");
				break;
			}

			LOG(INFO, "received OFFER, sending REQUEST (iface=%s)", iface->name);

			if (dhcp_send_request(client) < 0) {
				LOG(ERR, "dhcp_send_request: %s", strerror(errno));
				break;
			}

			client->state = DHCP_STATE_REQUESTING;
			LOG(INFO, "transitioned to REQUESTING state (iface=%u)", iface->id);
		}
		break;

	case DHCP_STATE_REQUESTING:
		if (msg_type == DHCP_ACK) {
			if (client->offered_ip == 0) {
				LOG(ERR, "invalid ACK (no offered IP)");
				break;
			}

			LOG(INFO, "received ACK, transitioning to BOUND (iface=%u)", iface->id);

			if (dhcp_configure_interface(client) < 0) {
				LOG(ERR, "failed to configure interface");
				break;
			}

			client->state = DHCP_STATE_BOUND;
			dhcp_schedule_timers(client);
			LOG(INFO,
			    "acquired IP " IP4_F " (lease=%u, T1=%u, T2=%u)",
			    &client->offered_ip,
			    client->lease_time,
			    client->renewal_time,
			    client->rebind_time);
		} else if (msg_type == DHCP_NAK) {
			LOG(WARNING, "received NAK, returning to INIT (iface=%u)", iface->id);
			client->state = DHCP_STATE_INIT;
		}
		break;

	case DHCP_STATE_BOUND:
		// Shouldn't receive DHCP messages while bound (unless it's a rogue server)
		LOG(DEBUG, "ignoring message in BOUND state");
		break;

	case DHCP_STATE_RENEWING:
	case DHCP_STATE_REBINDING:
		if (msg_type == DHCP_ACK) {
			LOG(INFO,
			    "lease renewed (state=%s, iface=%u)",
			    client->state == DHCP_STATE_RENEWING ? "RENEWING" : "REBINDING",
			    iface->id);

			client->state = DHCP_STATE_BOUND;
			dhcp_schedule_timers(client);

			LOG(INFO,
			    "lease extended (lease=%u, T1=%u, T2=%u)",
			    client->lease_time,
			    client->renewal_time,
			    client->rebind_time);
		} else if (msg_type == DHCP_NAK) {
			LOG(WARNING,
			    "received NAK during renewal, returning to INIT (iface=%u)",
			    iface->id);

			dhcp_cancel_timers(client);

			if (client->offered_ip != 0 && client->prefixlen != 0)
				addr4_delete(iface->id, client->offered_ip, client->prefixlen);
			if (client->router_ip != 0)
				rib4_delete(iface->vrf_id, 0, 0, GR_NH_T_L3);

			client->state = DHCP_STATE_INIT;
			client->offered_ip = 0;
			client->prefixlen = 0;
			client->server_ip = 0;
			client->router_ip = 0;
			client->xid = rte_rand();

			if (dhcp_send_discover(client) < 0) {
				LOG(ERR, "dhcp_send_discover: %s", strerror(errno));
				break;
			}

			client->state = DHCP_STATE_SELECTING;
		}
		break;

	default:
		LOG(WARNING, "received message in unexpected state %d", client->state);
		break;
	}

free:
	rte_pktmbuf_free(mbuf);
}

static void dhcp_init(struct event_base *ev_base) {
	dhcp_ev_base = ev_base;

	dhcp_output = gr_control_input_register_handler("eth_output", true);

	dhcp_mp = gr_pktmbuf_pool_get(SOCKET_ID_ANY, 512);
	if (dhcp_mp == NULL)
		ABORT("failed to get mempool");
}

static int dhcp_start(uint16_t iface_id) {
	struct dhcp_client *client;
	const struct iface *iface;

	iface = iface_from_id(iface_id);
	if (iface == NULL)
		return -errno;

	if (dhcp_clients[iface_id] != NULL)
		return errno_set(EEXIST);

	client = calloc(1, sizeof(*client));
	if (client == NULL)
		return errno_set(ENOMEM);

	client->iface_id = iface_id;
	client->state = DHCP_STATE_INIT;
	client->xid = rte_rand();

	dhcp_clients[iface_id] = client;

	if (dhcp_send_discover(client) < 0) {
		LOG(ERR, "dhcp_send_discover: %s", strerror(errno));
		free(client);
		dhcp_clients[iface_id] = NULL;
		return errno_set(EIO);
	}

	client->state = DHCP_STATE_SELECTING;

	LOG(INFO, "sent DISCOVER on iface %u (xid=0x%08x)", client->iface_id, client->xid);

	return 0;
}

static int dhcp_stop(uint16_t iface_id) {
	struct dhcp_client *client;
	const struct iface *iface;

	iface = iface_from_id(iface_id);
	if (iface == NULL)
		return -errno;

	client = dhcp_clients[iface_id];
	if (client == NULL)
		return errno_set(ENOENT);

	if (client->offered_ip != 0 && client->prefixlen != 0)
		addr4_delete(iface->id, client->offered_ip, client->prefixlen);
	if (client->router_ip != 0)
		rib4_delete(iface->vrf_id, 0, 0, GR_NH_T_L3);

	dhcp_cancel_timers(client);

	free(client);
	dhcp_clients[iface_id] = NULL;

	LOG(INFO, "stopped client on iface %s", iface->name);

	return 0;
}

struct rte_mempool *dhcp_get_mempool(void) {
	return dhcp_mp;
}

static struct api_out dhcp_list_handler(const void *, struct api_ctx *ctx) {
	struct dhcp_client *client;
	uint16_t iface_id;

	for (iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		client = dhcp_clients[iface_id];
		if (client == NULL)
			continue;

		struct gr_dhcp_status status = {
			.iface_id = client->iface_id,
			.state = client->state,
			.server_ip = client->server_ip,
			.assigned_ip = client->offered_ip,
			.lease_time = client->lease_time,
			.renewal_time = client->renewal_time,
			.rebind_time = client->rebind_time,
		};

		api_send(ctx, sizeof(status), &status);
	}

	return api_out(0, 0, NULL);
}

static struct api_out dhcp_start_handler(const void *request, struct api_ctx *) {
	const struct gr_dhcp_start_req *req = request;

	if (dhcp_start(req->iface_id) < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct api_out dhcp_stop_handler(const void *request, struct api_ctx *) {
	const struct gr_dhcp_stop_req *req = request;

	if (dhcp_stop(req->iface_id) < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static void dhcp_fini(struct event_base *) {
	for (uint16_t iface_id = 0; iface_id < MAX_IFACES; iface_id++) {
		if (dhcp_clients[iface_id] != NULL)
			dhcp_stop(iface_id);
	}
	gr_pktmbuf_pool_release(dhcp_mp, 512);
}

static struct gr_module dhcp_module = {
	.name = "dhcp",
	.depends_on = "graph,ipv4 address",
	.init = dhcp_init,
	.fini = dhcp_fini,
};

static struct gr_api_handler dhcp_list_api = {
	.name = "dhcp list",
	.request_type = GR_DHCP_LIST,
	.callback = dhcp_list_handler,
};

static struct gr_api_handler dhcp_start_api = {
	.name = "dhcp start",
	.request_type = GR_DHCP_START,
	.callback = dhcp_start_handler,
};

static struct gr_api_handler dhcp_stop_api = {
	.name = "dhcp stop",
	.request_type = GR_DHCP_STOP,
	.callback = dhcp_stop_handler,
};

RTE_INIT(dhcp_constructor) {
	gr_register_module(&dhcp_module);
	gr_register_api_handler(&dhcp_list_api);
	gr_register_api_handler(&dhcp_start_api);
	gr_register_api_handler(&dhcp_stop_api);
}
