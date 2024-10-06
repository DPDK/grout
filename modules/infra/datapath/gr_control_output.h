// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#ifndef _GR_CONTROL_OUTPUT_PATH
#define _GR_CONTROL_OUTPUT_PATH

#include "gr_mbuf.h"

#include <rte_graph.h>

#include <time.h>

/**
 * Callback definition when a packet is punted to the control plane.
 * It is up to the function to free the received mbuf.
 *
 * @param struct rte_mbuf *
 *   pointer to a mbuf, with the data offset set to the osi layer of
 *   the node which punted the packet.
 */
typedef void (*control_output_cb_t)(struct rte_mbuf *);

GR_MBUF_PRIV_DATA_TYPE(control_output_mbuf_data, { control_output_cb_t callback; });

#define GR_MBUF_PRIV_CTRLOUT_TYPE(type_name, fields)                                               \
	struct type_name {                                                                         \
		control_output_cb_t callback;                                                      \
		struct fields;                                                                     \
	};                                                                                         \
	static inline struct type_name *type_name(struct rte_mbuf *m) {                            \
		static_assert(sizeof(struct type_name) <= GR_MBUF_PRIV_MAX_SIZE);                  \
		return rte_mbuf_to_priv(m);                                                        \
	}

void signal_control_ouput_message(void);
int control_output_push(struct rte_mbuf *m);
#endif
