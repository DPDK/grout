// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include "control_queue.h"
#include "icmp6.h"
#include "ip6_datapath.h"
#include "mbuf.h"

#include <rte_mbuf.h>

static void icmp6_punt_cb(void *m, uintptr_t, const struct control_queue_drain *drain) {
	if (drain != NULL && mbuf_data(m)->iface == drain->obj) {
		rte_pktmbuf_free(m);
		return;
	}

	if (icmp6_punt_to_kernel(m) < 0)
		rte_pktmbuf_free(m);
}

RTE_INIT(icmp6_constructor) {
	icmp6_input_register_callback(ICMP6_TYPE_ECHO_REPLY, icmp6_punt_cb);
	icmp6_input_register_callback(ICMP6_ERR_DEST_UNREACH, icmp6_punt_cb);
	icmp6_input_register_callback(ICMP6_ERR_TTL_EXCEEDED, icmp6_punt_cb);
	icmp6_input_register_callback(ICMP6_ERR_PKT_TOO_BIG, icmp6_punt_cb);
	icmp6_input_register_callback(ICMP6_ERR_PARAM_PROBLEM, icmp6_punt_cb);
}
