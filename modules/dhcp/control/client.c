// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#include "client.h"

#include <gr_api.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
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

static int dhcp_configure_interface(struct dhcp_client *client) {
	const struct iface *iface;
	struct rte_ether_addr mac;
	struct nexthop *nh;
	uint8_t prefixlen;
	int ret;

	iface = iface_from_id(client->iface_id);
	if (iface == NULL)
		return errno_set(ENODEV);

	if (iface_get_eth_addr(iface, &mac) < 0 && errno != EOPNOTSUPP)
		return -errno;

	if (client->subnet_mask == 0) {
		LOG(ERR, "dhcp: server did not provide subnet mask, rejecting offer");
		return errno_set(EINVAL);
	}

	prefixlen = __builtin_popcount(rte_be_to_cpu_32(client->subnet_mask));

	struct gr_nexthop_base base = {
		.type = GR_NH_T_L3,
		.origin = GR_NH_ORIGIN_DHCP,
		.iface_id = iface->id,
		.vrf_id = iface->vrf_id,
	};
	struct gr_nexthop_info_l3 l3 = {
		.af = GR_AF_IP4,
		.ipv4 = client->offered_ip,
		.prefixlen = prefixlen,
		.flags = GR_NH_F_LOCAL | GR_NH_F_LINK,
		.state = GR_NH_S_REACHABLE,
		.mac = mac,
	};

	if ((nh = nexthop_new(&base, &l3)) == NULL)
		return -errno;

	ret = rib4_insert(iface->vrf_id, client->offered_ip, prefixlen, GR_NH_ORIGIN_LINK, nh);
	if (ret < 0) {
		LOG(ERR, "dhcp: failed to add address to RIB: %s", strerror(-ret));
		return ret;
	}

	LOG(INFO,
	    "dhcp: configured address " IP4_F "/%u on iface %u",
	    &client->offered_ip,
	    prefixlen,
	    iface->id);

	// Add default route if router option was provided
	if (client->router_ip != 0) {
		struct nexthop *gw_nh;

		struct gr_nexthop_base gw_base = {
			.type = GR_NH_T_L3,
			.origin = GR_NH_ORIGIN_DHCP,
			.iface_id = iface->id,
			.vrf_id = iface->vrf_id,
		};
		struct gr_nexthop_info_l3 gw_l3 = {
			.af = GR_AF_IP4,
			.ipv4 = client->router_ip,
			.prefixlen = 0,
			.flags = GR_NH_F_GATEWAY,
			.state = GR_NH_S_REACHABLE,
		};

		if ((gw_nh = nexthop_new(&gw_base, &gw_l3)) == NULL) {
			LOG(WARNING, "dhcp: failed to create gateway nexthop: %s", strerror(errno));
			return 0; // Continue even if gateway creation fails
		}

		ret = rib4_insert(iface->vrf_id, 0, 0, GR_NH_ORIGIN_DHCP, gw_nh);
		if (ret < 0) {
			LOG(WARNING, "dhcp: failed to add default route: %s", strerror(-ret));
		} else {
			LOG(INFO, "dhcp: added default route via " IP4_F, &client->router_ip);
		}
	}

	return 0;
}

static void dhcp_send_request(struct dhcp_client *client);

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
		    "dhcp: T1 timer fired but not in BOUND state (state=%d)",
		    client->state);
		return;
	}

	LOG(INFO, "dhcp: T1 timer expired, transitioning to RENEWING (iface=%u)", client->iface_id);
	client->state = DHCP_STATE_RENEWING;

	dhcp_send_request(client);
}

static void dhcp_t2_callback(evutil_socket_t, short, void *arg) {
	struct dhcp_client *client = arg;

	if (client->state != DHCP_STATE_RENEWING) {
		LOG(WARNING,
		    "dhcp: T2 timer fired but not in RENEWING state (state=%d)",
		    client->state);
		return;
	}

	LOG(INFO,
	    "dhcp: T2 timer expired, transitioning to REBINDING (iface=%u)",
	    client->iface_id);
	client->state = DHCP_STATE_REBINDING;

	dhcp_send_request(client);
}

static void dhcp_expire_callback(evutil_socket_t, short, void *arg) {
	struct dhcp_client *client = arg;
	const struct iface *iface;
	uint8_t prefixlen;

	LOG(WARNING, "dhcp: lease expired on iface %u", client->iface_id);

	iface = iface_from_id(client->iface_id);
	if (iface == NULL)
		return;

	if (client->subnet_mask == 0) {
		LOG(ERR, "dhcp: lease expired but no subnet mask stored, cannot delete routes");
		client->state = DHCP_STATE_INIT;
		return;
	}

	prefixlen = __builtin_popcount(rte_be_to_cpu_32(client->subnet_mask));

	if (client->offered_ip != 0)
		rib4_delete(iface->vrf_id, client->offered_ip, prefixlen, GR_NH_T_L3);
	if (client->router_ip != 0)
		rib4_delete(iface->vrf_id, 0, 0, GR_NH_T_L3);

	client->state = DHCP_STATE_INIT;
	client->offered_ip = 0;
	client->server_ip = 0;
	client->subnet_mask = 0;
	client->router_ip = 0;

	client->xid = rte_rand();
	struct rte_mbuf *m = dhcp_build_discover(client->iface_id, client->xid);
	if (m != NULL) {
		post_to_stack(dhcp_output, m);
		client->state = DHCP_STATE_SELECTING;
		LOG(INFO, "dhcp: lease expired, sent new DISCOVER (iface=%u)", client->iface_id);
	}
}

static void dhcp_send_request(struct dhcp_client *client) {
	struct rte_mbuf *m;

	m = dhcp_build_request(
		client->iface_id, client->xid, client->server_ip, client->offered_ip
	);
	if (m == NULL) {
		LOG(ERR, "dhcp: failed to build REQUEST for renewal");
		return;
	}

	post_to_stack(dhcp_output, m);
	LOG(INFO,
	    "dhcp: sent REQUEST for renewal (iface=%u, state=%s)",
	    client->iface_id,
	    client->state == DHCP_STATE_RENEWING ? "RENEWING" : "REBINDING");
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
		LOG(WARNING, "dhcp: failed to create T1 timer");
	}

	t2_tv.tv_sec = t2_secs;
	t2_tv.tv_usec = 0;
	client->t2_timer = evtimer_new(dhcp_ev_base, dhcp_t2_callback, client);
	if (client->t2_timer != NULL) {
		evtimer_add(client->t2_timer, &t2_tv);
	} else {
		LOG(WARNING, "dhcp: failed to create T2 timer");
	}

	expire_tv.tv_sec = client->lease_time;
	expire_tv.tv_usec = 0;
	client->expire_timer = evtimer_new(dhcp_ev_base, dhcp_expire_callback, client);
	if (client->expire_timer != NULL) {
		evtimer_add(client->expire_timer, &expire_tv);
	} else {
		LOG(WARNING, "dhcp: failed to create expire timer");
	}

	LOG(INFO,
	    "dhcp: scheduled timers T1=%us, T2=%us, expire=%us (iface=%u)",
	    t1_secs,
	    t2_secs,
	    client->lease_time,
	    client->iface_id);
}

void dhcp_input_cb(struct rte_mbuf *mbuf, const struct control_output_drain *drain) {
	dhcp_message_type_t msg_type = 0;
	const struct iface *iface = mbuf_data(mbuf)->iface;
	struct dhcp_client *client;
	struct rte_mbuf *response;

	// Check if packet references deleted interface.
	if (drain != NULL && drain->event == GR_EVENT_IFACE_REMOVE && iface == drain->obj)
		goto free;

	LOG(DEBUG, "dhcp_input_cb: received packet");

	if (iface == NULL) {
		LOG(ERR, "dhcp_input_cb: no interface in mbuf");
		goto free;
	}

	LOG(DEBUG, "dhcp_input_cb: packet on iface %u", iface->id);

	if (iface->id >= MAX_IFACES) {
		LOG(ERR, "dhcp_input_cb: iface %u exceeds MAX_IFACES", iface->id);
		goto free;
	}

	client = dhcp_clients[iface->id];
	if (client == NULL) {
		LOG(DEBUG, "dhcp_input_cb: no DHCP client on iface %u, ignoring", iface->id);
		goto free;
	}

	LOG(DEBUG, "dhcp_input_cb: processing packet for client in state %d", client->state);

	if (dhcp_parse_packet(mbuf, client, &msg_type) < 0) {
		LOG(ERR, "dhcp_input_cb: failed to parse DHCP packet on iface %u", iface->id);
		goto free;
	}

	switch (client->state) {
	case DHCP_STATE_SELECTING:
		if (msg_type == DHCP_OFFER) {
			if (client->server_ip == 0 || client->offered_ip == 0) {
				LOG(ERR, "dhcp: invalid OFFER (no server IP or offered IP)");
				break;
			}

			LOG(INFO, "dhcp: received OFFER, sending REQUEST (iface=%u)", iface->id);

			response = dhcp_build_request(
				client->iface_id, client->xid, client->server_ip, client->offered_ip
			);
			if (response == NULL) {
				LOG(ERR, "dhcp: failed to build REQUEST");
				break;
			}

			if (post_to_stack(dhcp_output, response) < 0) {
				LOG(ERR, "dhcp: failed to send REQUEST");
				rte_pktmbuf_free(response);
				break;
			}

			client->state = DHCP_STATE_REQUESTING;
			LOG(INFO, "dhcp: transitioned to REQUESTING state (iface=%u)", iface->id);
		}
		break;

	case DHCP_STATE_REQUESTING:
		if (msg_type == DHCP_ACK) {
			if (client->offered_ip == 0) {
				LOG(ERR, "dhcp: invalid ACK (no offered IP)");
				break;
			}

			LOG(INFO,
			    "dhcp: received ACK, transitioning to BOUND (iface=%u)",
			    iface->id);

			if (dhcp_configure_interface(client) < 0) {
				LOG(ERR, "dhcp: failed to configure interface");
				break;
			}

			client->state = DHCP_STATE_BOUND;
			dhcp_schedule_timers(client);
			LOG(INFO,
			    "dhcp: acquired IP " IP4_F " (lease=%u, T1=%u, T2=%u)",
			    &client->offered_ip,
			    client->lease_time,
			    client->renewal_time,
			    client->rebind_time);
		} else if (msg_type == DHCP_NAK) {
			LOG(WARNING, "dhcp: received NAK, returning to INIT (iface=%u)", iface->id);
			client->state = DHCP_STATE_INIT;
		}
		break;

	case DHCP_STATE_BOUND:
		// Shouldn't receive DHCP messages while bound (unless it's a rogue server)
		LOG(DEBUG, "dhcp: ignoring message in BOUND state");
		break;

	case DHCP_STATE_RENEWING:
	case DHCP_STATE_REBINDING:
		if (msg_type == DHCP_ACK) {
			LOG(INFO,
			    "dhcp: lease renewed (state=%s, iface=%u)",
			    client->state == DHCP_STATE_RENEWING ? "RENEWING" : "REBINDING",
			    iface->id);

			client->state = DHCP_STATE_BOUND;
			dhcp_schedule_timers(client);

			LOG(INFO,
			    "dhcp: lease extended (lease=%u, T1=%u, T2=%u)",
			    client->lease_time,
			    client->renewal_time,
			    client->rebind_time);
		} else if (msg_type == DHCP_NAK) {
			LOG(WARNING,
			    "dhcp: received NAK during renewal, returning to INIT (iface=%u)",
			    iface->id);

			dhcp_cancel_timers(client);

			if (client->subnet_mask != 0) {
				uint8_t prefixlen = __builtin_popcount(
					rte_be_to_cpu_32(client->subnet_mask)
				);
				if (client->offered_ip != 0)
					rib4_delete(
						iface->vrf_id,
						client->offered_ip,
						prefixlen,
						GR_NH_T_L3
					);
			} else if (client->offered_ip != 0) {
				LOG(ERR,
				    "dhcp: NAK received but no subnet mask stored, cannot delete "
				    "address route");
			}
			if (client->router_ip != 0)
				rib4_delete(iface->vrf_id, 0, 0, GR_NH_T_L3);

			client->state = DHCP_STATE_INIT;
			client->offered_ip = 0;
			client->server_ip = 0;

			client->xid = rte_rand();
			response = dhcp_build_discover(client->iface_id, client->xid);
			if (response != NULL) {
				post_to_stack(dhcp_output, response);
				client->state = DHCP_STATE_SELECTING;
			}
		}
		break;

	default:
		LOG(WARNING, "dhcp: received message in unexpected state %d", client->state);
		break;
	}

free:
	rte_pktmbuf_free(mbuf);
}

static void dhcp_init(struct event_base *ev_base) {
	dhcp_ev_base = ev_base;

	dhcp_input_register_port();

	dhcp_output = gr_control_input_register_handler("eth_output", true);

	dhcp_mp = gr_pktmbuf_pool_get(SOCKET_ID_ANY, 512);
	if (dhcp_mp == NULL)
		ABORT("dhcp: failed to get mempool");

	LOG(INFO, "dhcp: module initialized");
}

int dhcp_start(uint16_t iface_id) {
	struct dhcp_client *client;
	struct rte_mbuf *m;
	uint32_t xid;

	if (iface_id >= MAX_IFACES) {
		errno = EINVAL;
		return -1;
	}

	if (iface_from_id(iface_id) == NULL) {
		errno = ENODEV;
		return -1;
	}

	if (dhcp_clients[iface_id] != NULL) {
		LOG(WARNING, "dhcp: client already running on iface %u", iface_id);
		errno = EEXIST;
		return -1;
	}

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		LOG(ERR, "dhcp: failed to allocate client for iface %u", iface_id);
		errno = ENOMEM;
		return -1;
	}

	xid = rte_rand();

	client->iface_id = iface_id;
	client->state = DHCP_STATE_INIT;
	client->xid = xid;

	dhcp_clients[iface_id] = client;

	m = dhcp_build_discover(iface_id, xid);
	if (m == NULL) {
		LOG(ERR, "dhcp: failed to build DISCOVER for iface %u", iface_id);
		free(client);
		dhcp_clients[iface_id] = NULL;
		errno = ENOMEM;
		return -1;
	}

	if (post_to_stack(dhcp_output, m) < 0) {
		LOG(ERR, "dhcp: failed to send DISCOVER for iface %u", iface_id);
		rte_pktmbuf_free(m);
		free(client);
		dhcp_clients[iface_id] = NULL;
		errno = EIO;
		return -1;
	}

	client->state = DHCP_STATE_SELECTING;

	LOG(INFO, "dhcp: sent DISCOVER on iface %u (xid=0x%08x)", iface_id, xid);
	return 0;
}

void dhcp_stop(uint16_t iface_id) {
	struct dhcp_client *client;
	const struct iface *iface;
	uint8_t prefixlen;
	int ret;

	errno = 0;

	if (iface_id >= MAX_IFACES) {
		errno = EINVAL;
		return;
	}

	client = dhcp_clients[iface_id];
	if (client == NULL) {
		LOG(WARNING, "dhcp: no client running on iface %u", iface_id);
		errno = ENOENT;
		return;
	}

	iface = iface_from_id(iface_id);
	if (iface == NULL) {
		errno = ENODEV;
		return;
	}

	if (client->offered_ip != 0) {
		if (client->subnet_mask == 0) {
			LOG(ERR,
			    "dhcp: stopping client but no subnet mask stored, cannot delete "
			    "address route");
		} else {
			prefixlen = __builtin_popcount(rte_be_to_cpu_32(client->subnet_mask));
			ret = rib4_delete(iface->vrf_id, client->offered_ip, prefixlen, GR_NH_T_L3);
			if (ret < 0) {
				LOG(WARNING,
				    "dhcp: failed to remove address route: %s",
				    strerror(-ret));
			} else {
				LOG(INFO,
				    "dhcp: removed address " IP4_F "/%u from iface %u",
				    &client->offered_ip,
				    prefixlen,
				    iface_id);
			}
		}
	}

	if (client->router_ip != 0) {
		ret = rib4_delete(iface->vrf_id, 0, 0, GR_NH_T_L3);
		if (ret < 0) {
			LOG(WARNING, "dhcp: failed to remove default route: %s", strerror(-ret));
		} else {
			LOG(INFO, "dhcp: removed default route via " IP4_F, &client->router_ip);
		}
	}

	dhcp_cancel_timers(client);

	free(client);
	dhcp_clients[iface_id] = NULL;

	LOG(INFO, "dhcp: stopped client on iface %u", iface_id);
}

struct rte_mempool *dhcp_get_mempool(void) {
	return dhcp_mp;
}

control_input_t dhcp_get_output(void) {
	return dhcp_output;
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

	dhcp_stop(req->iface_id);
	if (errno != 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static void dhcp_fini(struct event_base *) {
	gr_pktmbuf_pool_release(dhcp_mp, 512);
	LOG(INFO, "dhcp: module finalized");
}

static struct gr_module dhcp_module = {
	.name = "dhcp",
	.init = dhcp_init,
	.fini = dhcp_fini,
	.depends_on = "graph",
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
