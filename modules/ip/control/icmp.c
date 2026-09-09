// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "control_queue.h"
#include "ip4_datapath.h"
#include "mbuf.h"

#include <rte_icmp.h>
#include <rte_mbuf.h>

static void icmp_punt_cb(void *m, uintptr_t, const struct control_queue_drain *drain) {
	if (drain != NULL && mbuf_data(m)->iface == drain->obj) {
		rte_pktmbuf_free(m);
		return;
	}

	if (icmp_punt_to_kernel(m) < 0)
		rte_pktmbuf_free(m);
}

RTE_INIT(icmp_constructor) {
	icmp_input_register_callback(RTE_ICMP_TYPE_DEST_UNREACHABLE, icmp_punt_cb);
	icmp_input_register_callback(RTE_ICMP_TYPE_TTL_EXCEEDED, icmp_punt_cb);
	icmp_input_register_callback(RTE_ICMP_TYPE_PARAM_PROBLEM, icmp_punt_cb);
	icmp_input_register_callback(RTE_ICMP_TYPE_ECHO_REPLY, icmp_punt_cb);
}
