// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_output.h>
#include <gr_event.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_mbuf.h>
#include <gr_module.h>
#include <gr_nexthop.h>

#include <event2/event.h>

#include <sys/eventfd.h>
#include <unistd.h>

static struct rte_ring *ctrlout_ring;

int control_output_enqueue(struct rte_mbuf *m) {
	return rte_ring_enqueue(ctrlout_ring, m);
}

static void control_output_poll(evutil_socket_t fd, short what, void *priv) {
	struct control_output_drain *drain = priv;
	struct control_output_mbuf_data *data;
	void *mbufs[RTE_GRAPH_BURST_SIZE];
	eventfd_t efd_counter;
	unsigned count;

	if (!(what & EV_READ))
		return;

	eventfd_read(fd, &efd_counter);
	errno = 0; // silence errors

	count = rte_ring_dequeue_burst(ctrlout_ring, mbufs, ARRAY_DIM(mbufs), NULL);
	for (unsigned i = 0; i < count; i++) {
		struct rte_mbuf *mbuf = mbufs[i];
		data = control_output_mbuf_data(mbuf);

		if (data->callback != NULL)
			data->callback(mbuf, drain);
		else
			rte_pktmbuf_free(mbuf);
	}
}

static struct event *ctrlout_ev;
static int event_fd = -1;

void control_output_done(void) {
	eventfd_write(event_fd, 1);
}

// When interfaces or nexthops are deleted, drain the control output ring
// to free any packets that reference the deleted object. This prevents
// callbacks from being invoked with dangling pointers.
static void event_handler(uint32_t event, const void *obj) {
	struct control_output_drain drain = {event, obj};
	control_output_poll(event_fd, EV_READ, &drain);
}

static struct gr_event_subscription event_sub = {
	.callback = event_handler,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_IFACE_REMOVE,
		GR_EVENT_NEXTHOP_DELETE,
	},
};

static void control_output_init(struct event_base *ev_base) {
	ctrlout_ring = rte_ring_create(
		"control_output",
		RTE_GRAPH_BURST_SIZE * 4,
		SOCKET_ID_ANY,
		RING_F_MP_RTS_ENQ | RING_F_SC_DEQ
	);
	if (ctrlout_ring == NULL)
		ABORT("rte_ring_create(ctrl_output): %s", rte_strerror(rte_errno));

	event_fd = eventfd(0, EFD_NONBLOCK);
	if (event_fd < 0)
		ABORT("eventfd(): %s", strerror(errno));

	ctrlout_ev = event_new(ev_base, event_fd, EV_READ | EV_PERSIST, control_output_poll, NULL);
	if (ctrlout_ev == NULL)
		ABORT("event_new() failed");

	if (event_add(ctrlout_ev, NULL) < 0)
		ABORT("event_add() failed");
}

static void control_output_fini(struct event_base *) {
	if (event_fd != -1)
		close(event_fd);
	if (ctrlout_ev != NULL)
		event_free(ctrlout_ev);
	rte_ring_free(ctrlout_ring);
}

static struct gr_module control_output_module = {
	.name = "control_output",
	.depends_on = "graph",
	.init = control_output_init,
	.fini = control_output_fini,
};

RTE_INIT(control_output_module_init) {
	gr_register_module(&control_output_module);
	gr_event_subscribe(&event_sub);
}
