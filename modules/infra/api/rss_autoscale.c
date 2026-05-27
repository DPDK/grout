// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Maxime Leroy, Free Mobile

#include "iface.h"
#include "module.h"
#include "port.h"
#include "rss_autoscale.h"

#include <gr_infra.h>

#include <errno.h>
#include <stdlib.h>

static struct api_out rss_autoscale_list(const void * /*request*/, struct api_ctx *ctx) {
	struct iface *iface = NULL;
	while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
		struct iface_info_port *p = iface_info_port(iface);
		struct gr_rss_autoscale_port_state s = {
			.iface_id = iface->id,
		};
		uint16_t n_active = 0, n_reco = 0, min_n = 0, max_n = 0;
		uint16_t cap = 0, floor = 0;

		// Skip ports without state or PMD RETA support.
		if (rss_autoscale_port_state_get(
			    p->port_id, &n_active, &n_reco, &cap, &floor, &max_n, &min_n
		    )
		    < 0)
			continue;
		s.n_active = n_active;
		s.n_load_recommended = n_reco;
		s.min_n = min_n;
		s.max_n = max_n;
		s.cap = cap;
		s.floor = floor;
		api_send(ctx, sizeof(s), &s);
	}
	return api_out(0, 0, NULL);
}

RTE_INIT(_init) {
	api_handler(GR_RSS_AUTOSCALE_LIST, rss_autoscale_list);
}
