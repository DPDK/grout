// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_control_output.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_mbuf.h>
#include <gr_module.h>

#include <event2/event.h>
#include <rte_ether.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>

static struct rte_ring *ctrlout_ring;

int control_output_enqueue(struct rte_mbuf *m) {
	return rte_ring_enqueue(ctrlout_ring, m);
}

static void control_output_poll(evutil_socket_t, short, void *) {
	struct control_output_mbuf_data *data;
	struct rte_mbuf *mbuf;
	void *ring_item;

	while (rte_ring_dequeue(ctrlout_ring, &ring_item) == 0) {
		mbuf = ring_item;
		data = control_output_mbuf_data(mbuf);
		if (data->callback != NULL)
			control_output_mbuf_data(mbuf)->callback(mbuf);
		else
			rte_pktmbuf_free(mbuf);
	}
}

static struct event *ctrlout_ev;

void control_output_done(void) {
	evuser_trigger(ctrlout_ev);
}

static void control_output_init(struct event_base *ev_base) {
	ctrlout_ring = rte_ring_create(
		"control_output",
		RTE_GRAPH_BURST_SIZE * 4,
		SOCKET_ID_ANY,
		RING_F_MP_RTS_ENQ | RING_F_SC_DEQ
	);
	if (ctrlout_ring == NULL)
		ABORT("rte_ring_create(ctrl_output): %s", rte_strerror(rte_errno));

	ctrlout_ev = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, control_output_poll, NULL);
	if (ctrlout_ev == NULL)
		ABORT("event_new() failed");
}

static void control_output_fini(struct event_base *) {
	control_output_done();
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
}
