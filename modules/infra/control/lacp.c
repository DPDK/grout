// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_bond.h>
#include <gr_clock.h>
#include <gr_control_input.h>
#include <gr_control_output.h>
#include <gr_eth.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_lacp.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_module.h>
#include <gr_port.h>

#include <event2/event.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include <stdbool.h>
#include <string.h>

static struct event *lacp_timer;

static void update_active_members(struct iface *iface) {
	struct iface_info_bond *bond = iface_info_bond(iface);
	const struct lacp_info *lacp;
	struct iface *member;

	bond->n_active_members = 0;
	for (uint8_t i = 0; i < bond->n_members; i++) {
		member = bond->members[i];
		lacp = &bond->lacp[i];

		if ((member->flags & GR_IFACE_F_UP) && (member->state & GR_IFACE_S_RUNNING)
		    && lacp->state == LACP_MEMBER_ACTIVE) {
			LOG(DEBUG, "bond %s member %s active", iface->name, member->name);
			bond->active_members[bond->n_active_members++] = member;
		}
	}
	if (bond->n_active_members > 0) {
		if (!(iface->state & GR_IFACE_S_RUNNING)) {
			iface->state |= GR_IFACE_S_RUNNING;
			if (iface->flags & GR_IFACE_F_UP) {
				gr_event_push(GR_EVENT_IFACE_STATUS_UP, iface);
			}
		}
	} else {
		if (iface->state & GR_IFACE_S_RUNNING) {
			iface->state &= ~GR_IFACE_S_RUNNING;
			gr_event_push(GR_EVENT_IFACE_STATUS_DOWN, iface);
		}
	}
}

void lacp_input_cb(struct rte_mbuf *mbuf) {
	struct control_output_mbuf_data *ctrl_data = control_output_mbuf_data(mbuf);
	const struct iface_info_port *port;
	const struct iface *port_iface;
	struct iface_info_bond *bond;
	const struct lacp_pdu *pdu;
	struct iface *bond_iface;
	struct lacp_info *lacp;

	memcpy(&port_iface, ctrl_data->cb_data, sizeof(struct iface *));
	if (port_iface->type != GR_IFACE_TYPE_PORT) {
		LOG(DEBUG, "interface %s is not a port", port_iface->name);
		goto out;
	}
	port = iface_info_port(port_iface);
	bond_iface = iface_from_id(port->bond_iface_id);
	if (bond_iface == NULL) {
		LOG(DEBUG, "bond %u has disappeared", port->bond_iface_id);
		goto out;
	}
	bond = iface_info_bond(bond_iface);
	if (bond->mode != GR_BOND_MODE_LACP) {
		LOG(DEBUG, "bond %s is not lacp", bond_iface->name);
		goto out;
	}

	lacp = NULL;
	for (uint8_t i = 0; i < bond->n_members; i++) {
		if (bond->members[i] == port_iface) {
			lacp = &bond->lacp[i];
			break;
		}
	}
	if (lacp == NULL) {
		LOG(DEBUG, "port %s is not part of bond %s", port_iface->name, bond_iface->name);
		goto out;
	}

	pdu = rte_pktmbuf_mtod(mbuf, struct lacp_pdu *);

	// Store partner information from received PDU
	lacp->remote = pdu->actor;
	lacp->last_rx = gr_clock_us();

	// Save old member state to detect changes
	lacp_member_state_t old_state = lacp->state;

	lacp->state = LACP_MEMBER_ACTIVE;
	lacp->local.state |= LACP_STATE_SYNCHRONIZED;
	lacp->local.state &= ~(LACP_STATE_EXPIRED | LACP_STATE_DEFAULTED);

	// Update bond active members list if member state changed
	if (old_state != lacp->state)
		update_active_members(bond_iface);

	// Always transmit a response when we receive a PDU
	lacp->need_to_transmit = true;
	event_active(lacp_timer, 0, 0);

out:
	rte_pktmbuf_free(mbuf);
}

static int lacp_send(const struct iface *port, const struct lacp_info *lacp) {
	struct lacp_pdu pdu = {
		.subtype = LACP_SUBTYPE,
		.version = LACP_VERSION_1,
		.actor_type = LACP_TYPE_ACTOR,
		.actor_len = LACP_LEN_ACTOR,
		.actor = lacp->local,
		.partner_type = LACP_TYPE_PARTNER,
		.partner_len = LACP_LEN_PARTNER,
		.partner = lacp->remote,
		.collector_type = LACP_TYPE_COLLECTOR,
		.collector_len = LACP_LEN_COLLECTOR,
		.collector_max_delay = RTE_BE16(0),
		.terminator_type = LACP_TYPE_TERMINATOR,
		.terminator_len = LACP_LEN_TERMINATOR,
	};
	return lacp_send_pdu(port, &pdu);
}

// Periodic timer callback to send LACP PDUs and check timeouts
static void lacp_periodic(evutil_socket_t, short, void *) {
	struct iface_info_bond *bond;
	struct iface *port, *iface;
	struct lacp_info *lacp;
	clock_t now, timeout;

	now = gr_clock_us();

	iface = NULL;
	while ((iface = iface_next(GR_IFACE_TYPE_BOND, iface)) != NULL) {
		bond = iface_info_bond(iface);
		if (bond->mode != GR_BOND_MODE_LACP)
			continue;

		bool active_changed = false;

		for (uint8_t i = 0; i < bond->n_members; i++) {
			lacp = &bond->lacp[i];
			port = bond->members[i];

			// Check for timeout if we've received at least one PDU
			if (lacp->last_rx != 0) {
				if (lacp->local.state & LACP_STATE_FAST)
					timeout = LACP_SHORT_TIMEOUT * US_PER_S;
				else
					timeout = LACP_LONG_TIMEOUT * US_PER_S;

				if (now - lacp->last_rx > timeout
				    && lacp->state == LACP_MEMBER_ACTIVE) {
					// Partner timed out - enter FAILED state
					lacp->state = LACP_MEMBER_FAILED;
					lacp->local.state &= ~LACP_STATE_SYNCHRONIZED;
					lacp->local.state |= LACP_STATE_EXPIRED;
					lacp->local.state |= LACP_STATE_DEFAULTED;
					lacp->need_to_transmit = true;
					active_changed = true;
					LOG(WARNING,
					    "LACP timeout on %s member %s",
					    iface->name,
					    port->name);
				}
			}

			// Send LACP PDU if needed
			if (!lacp->need_to_transmit && lacp->next_tx > now && lacp->last_rx > 0)
				continue;
			if (!(port->flags & GR_IFACE_F_UP) || !(port->state & GR_IFACE_S_RUNNING))
				continue;

			if (lacp_send(port, lacp) < 0)
				LOG(ERR, "lacp_send: %s", strerror(errno));

			lacp->need_to_transmit = false;
			if (lacp->remote.state & LACP_STATE_FAST)
				lacp->next_tx = now + LACP_SHORT_TIMEOUT * US_PER_S;
			else
				lacp->next_tx = now + LACP_LONG_TIMEOUT * US_PER_S;
		}

		// Update active members list if any port timed out
		if (active_changed)
			update_active_members(iface);
	}
}

static void lacp_init(struct event_base *ev_base) {
	// Create periodic timer (runs every 1 second for fast LACP)
	lacp_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, lacp_periodic, NULL);
	if (lacp_timer == NULL)
		ABORT("event_new() failed");

	if (event_add(lacp_timer, &(struct timeval) {.tv_sec = LACP_FAST_PERIOD}) < 0)
		ABORT("event_add() failed");
}

static void lacp_fini(struct event_base *) {
	if (lacp_timer != NULL)
		event_free(lacp_timer);
}

static struct gr_module lacp_module = {
	.name = "lacp",
	.init = lacp_init,
	.fini = lacp_fini,
};

RTE_INIT(lacp_constructor) {
	gr_register_module(&lacp_module);
}
