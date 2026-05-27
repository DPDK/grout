// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Maxime Leroy, Free Mobile

#include "config.h"
#include "control_queue.h"
#include "event.h"
#include "iface.h"
#include "log.h"
#include "module.h"
#include "port.h"
#include "port_scale.h"
#include "rss_autoscale.h"
#include "worker.h"

#include <gr_infra.h>
#include <gr_string.h>

#include <event2/event.h>
#include <rte_ethdev.h>
#include <rte_graph.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

LOG_TYPE("rss_autoscale");

struct rxq_health rxq_health[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES_PER_PORT];

// Worker clears consec_*/health on its next poll (keeps consec_* single-writer).
static void rxq_health_reset(struct rxq_health *h) {
	atomic_store_explicit(&h->reset_pending, true, memory_order_relaxed);
}

#define SCALE_DOWN_PERIOD_S 600
#define DEFERRED_PARK_US 100000

struct rss_autoscale_port_state {
	uint16_t port_id;
	uint16_t n_active;
	uint16_t n_load_recommended;
	struct port_scale_caps caps;
	uint16_t policy_cap; // 0 = unset; cap < floor: cap wins
	uint16_t policy_floor;
	uint64_t prev_busy_cycles;
	uint64_t prev_total_cycles;
	struct event *scale_down_timer;
};

static struct rss_autoscale_port_state *port_states[RTE_MAX_ETHPORTS];
static struct event_base *rss_autoscale_ev_base;
static struct event *deferred_park_event;

static struct iface_info_port *port_info_from_id(uint16_t port_id) {
	const struct iface *i = port_get_iface(port_id);
	if (i == NULL)
		return NULL;
	return iface_info_port(i);
}

static struct rss_autoscale_port_state *state_get(uint16_t port_id) {
	if (port_id >= RTE_MAX_ETHPORTS)
		return NULL;
	return port_states[port_id];
}

bool rss_autoscale_port_enabled(uint16_t port_id) {
	struct rss_autoscale_port_state *s = state_get(port_id);
	return s != NULL && s->caps.supports_scale;
}

static struct rss_autoscale_port_state *state_ensure(uint16_t port_id) {
	if (port_id >= RTE_MAX_ETHPORTS)
		return NULL;
	if (port_states[port_id] != NULL)
		return port_states[port_id];
	struct rss_autoscale_port_state *s = calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;
	s->port_id = port_id;
	port_states[port_id] = s;
	return s;
}

// Lazily populate caps and filter allowed_n by cluster_size so scaling
// steps stay aligned with cache-sharing groups.
static int caps_ensure(struct rss_autoscale_port_state *s) {
	if (s->caps.allowed_n != NULL)
		return s->caps.supports_scale ? 0 : -ENOTSUP;
	struct iface_info_port *p = port_info_from_id(s->port_id);
	if (p == NULL)
		return -ENODEV;
	int ret = port_scale_caps_get(p, &s->caps);
	if (ret < 0)
		return ret;
	if (!s->caps.supports_scale)
		return -ENOTSUP;

	uint16_t cluster_size = gr_config.rss_autoscale;
	if (cluster_size > 1 && s->caps.allowed_n != NULL) {
		size_t w = 0;
		for (size_t r = 0; r < s->caps.allowed_count; r++) {
			if (s->caps.allowed_n[r] % cluster_size == 0)
				s->caps.allowed_n[w++] = s->caps.allowed_n[r];
		}
		s->caps.allowed_count = w;
		if (w <= 1) {
			// Need at least 2 allowed values to scale dynamically. Free
			// so the allowed_n != NULL short-circuit at the top does not
			// later treat this as a cached success.
			LOG(NOTICE,
			    "port %u: cluster_size=%u leaves %zu allowed N value(s), "
			    "not managed by rss-autoscale",
			    s->port_id,
			    cluster_size,
			    w);
			port_scale_caps_free(&s->caps);
			return -ENOTSUP;
		}
	}
	return 0;
}

static void
port_worker_cycles(uint16_t port_id, uint16_t n_active, uint64_t *out_busy, uint64_t *out_total);

// On success, rearms the scale-down timer on a fresh CPU baseline so
// the next fire averages only post-apply cycles.
static int do_apply(struct rss_autoscale_port_state *s, uint16_t n_new) {
	struct iface_info_port *p = port_info_from_id(s->port_id);
	if (p == NULL)
		return -ENODEV;
	int ret = port_scale_apply(p, n_new);
	if (ret < 0)
		return ret;
	LOG(INFO, "port %u: dist_size %u -> %u", s->port_id, s->n_active, n_new);
	// Newly-activated queues may carry stale idle latched during a
	// previous deactivation drain. Clear their health so the next
	// !any_idle check is not blocked by them.
	for (uint16_t q = s->n_active; q < n_new; q++)
		rxq_health_reset(&rxq_health[s->port_id][q]);
	s->n_active = n_new;
	if (s->n_load_recommended == 0)
		s->n_load_recommended = n_new;
	if (s->scale_down_timer != NULL) {
		port_worker_cycles(s->port_id, n_new, &s->prev_busy_cycles, &s->prev_total_cycles);
		struct timeval tv = {.tv_sec = SCALE_DOWN_PERIOD_S};
		event_del(s->scale_down_timer);
		if (event_add(s->scale_down_timer, &tv) < 0)
			LOG(WARNING, "port %u: scale-down timer rearm failed", s->port_id);
	}
	return 0;
}

static void apply_unpark_all(void);
static void apply_park_all(void);
static void schedule_deferred_park(void);
static void scale_down_timer_cb(evutil_socket_t fd, short what, void *arg);

static uint16_t clamp_to_policy(struct rss_autoscale_port_state *s) {
	uint16_t target = s->n_active;
	if (s->policy_floor > 0 && target < s->policy_floor)
		target = s->policy_floor;
	if (s->policy_cap > 0 && target > s->policy_cap)
		target = s->policy_cap;
	return target;
}

static bool caps_contains(const struct port_scale_caps *caps, uint16_t n) {
	for (size_t i = 0; i < caps->allowed_count; i++) {
		if (caps->allowed_n[i] == n)
			return true;
	}
	return false;
}

// Shared logic for set_cap / set_floor. Caller provides the offset of the
// policy field inside rss_autoscale_port_state and a name for the log.
static int set_policy(uint16_t port_id, size_t policy_offset, uint16_t n, const char *name) {
	if (n > 0 && !gr_config.rss_autoscale)
		return -ENOTSUP;
	struct rss_autoscale_port_state *s = (n == 0) ? state_get(port_id) : state_ensure(port_id);
	if (s == NULL)
		return n == 0 ? 0 : -ENOMEM;
	if (n > 0) {
		if (s->n_active == 0)
			return -ENOTSUP;
		int ret = caps_ensure(s);
		if (ret < 0)
			return ret;
		if (!caps_contains(&s->caps, n))
			return -EINVAL;
	}
	uint16_t *policy = (uint16_t *)((char *)s + policy_offset);
	uint16_t saved = *policy;
	*policy = n;
	if (s->caps.supports_scale) {
		uint16_t target = clamp_to_policy(s);
		if (target != s->n_active && s->n_active > 0) {
			int ret = do_apply(s, target);
			if (ret < 0) {
				*policy = saved;
				return ret;
			}
			apply_unpark_all();
			schedule_deferred_park();
		}
	}
	LOG(INFO, "port %u: %s %s", port_id, name, n == 0 ? "cleared" : "set");
	return 0;
}

int rss_autoscale_set_cap(uint16_t port_id, uint16_t cap_n) {
	return set_policy(
		port_id, offsetof(struct rss_autoscale_port_state, policy_cap), cap_n, "cap"
	);
}

int rss_autoscale_set_floor(uint16_t port_id, uint16_t floor_n) {
	return set_policy(
		port_id, offsetof(struct rss_autoscale_port_state, policy_floor), floor_n, "floor"
	);
}

static void rss_autoscale_on_iface_post_add(uint32_t /*event*/, const void *obj) {
	const struct iface *iface = obj;

	if (iface->type != GR_IFACE_TYPE_PORT)
		return;
	if (!gr_config.rss_autoscale)
		return;

	const struct iface_info_port *p = iface_info_port(iface);
	struct rss_autoscale_port_state *s = state_ensure(p->port_id);
	if (s == NULL)
		return;

	int ret = caps_ensure(s);
	if (ret == -ENOTSUP)
		return;
	if (ret < 0) {
		LOG(WARNING, "port %u: caps_ensure failed: %s", p->port_id, strerror(-ret));
		return;
	}

	if (s->scale_down_timer == NULL && rss_autoscale_ev_base != NULL) {
		s->scale_down_timer = event_new(
			rss_autoscale_ev_base, -1, EV_PERSIST, scale_down_timer_cb, s
		);
		if (s->scale_down_timer == NULL)
			LOG(WARNING, "port %u: scale-down timer alloc failed", p->port_id);
	}

	uint16_t pin = gr_config.rss_autoscale;
	if (s->policy_floor > 0 && pin < s->policy_floor)
		pin = s->policy_floor;
	if (s->policy_cap > 0 && pin > s->policy_cap)
		pin = s->policy_cap;
	if (!do_apply(s, pin)) {
		apply_unpark_all();
		schedule_deferred_park();
	} else {
		// Pin failed: leave the HW on its default RSS distribution and
		// mark the port unscalable. Parking would strand workers on
		// queues the HW still routes traffic to.
		LOG(WARNING,
		    "port %u: initial pin to N=%u failed, leaving default RSS",
		    p->port_id,
		    pin);
		if (s->scale_down_timer != NULL) {
			event_del(s->scale_down_timer);
			event_free(s->scale_down_timer);
			s->scale_down_timer = NULL;
		}
		port_scale_caps_free(&s->caps);
	}
}

static void rss_autoscale_on_iface_remove(uint32_t /*event*/, const void *obj) {
	const struct iface *iface = obj;
	if (iface->type != GR_IFACE_TYPE_PORT)
		return;
	const struct iface_info_port *p = iface_info_port(iface);
	struct rss_autoscale_port_state *s = state_get(p->port_id);
	if (s == NULL)
		return;
	if (s->scale_down_timer != NULL) {
		event_del(s->scale_down_timer);
		event_free(s->scale_down_timer);
	}
	port_scale_caps_free(&s->caps);
	free(s);
	port_states[p->port_id] = NULL;
	for (uint16_t q = 0; q < RTE_MAX_QUEUES_PER_PORT; q++)
		rxq_health_reset(&rxq_health[p->port_id][q]);
}

// Port reconfig (e.g. operator changed nb-rxqs): drop cached state and
// re-pin from scratch so caps and rxq_health match the new HW layout.
static void rss_autoscale_on_iface_post_reconfig(uint32_t event, const void *obj) {
	rss_autoscale_on_iface_remove(event, obj);
	rss_autoscale_on_iface_post_add(event, obj);
}

static bool worker_has_active_rxq(const struct worker *w) {
	struct queue_map *qmap;
	vec_foreach_ref (qmap, w->rxqs) {
		struct rss_autoscale_port_state *ps = state_get(qmap->port_id);
		// Ports unmanaged by the controller (no state, PMD without
		// RETA, pin failed, or initial pin not yet applied) keep all
		// workers awake: parking them would strand queues the HW
		// still distributes traffic to.
		if (ps == NULL || !ps->caps.supports_scale || ps->n_active == 0)
			return true;
		if (qmap->queue_id < ps->n_active)
			return true;
	}
	return false;
}

static void apply_unpark_all(void) {
	struct worker *w;
	STAILQ_FOREACH (w, &workers, next) {
		if (worker_is_paused(w) && worker_has_active_rxq(w))
			worker_unpark(w);
	}
}

static void apply_park_all(void) {
	struct worker *w;
	STAILQ_FOREACH (w, &workers, next) {
		if (!worker_is_paused(w) && !worker_has_active_rxq(w))
			worker_park(w);
	}
}

static void deferred_park_cb(evutil_socket_t /*fd*/, short /*what*/, void * /*arg*/) {
	apply_park_all();
}

// First schedule arms the timer; subsequent ones during the window are
// no-ops so a burst of RETA changes still fires a single park sweep.
static void schedule_deferred_park(void) {
	if (deferred_park_event == NULL)
		return;
	if (event_pending(deferred_park_event, EV_TIMEOUT, NULL))
		return;
	struct timeval tv = {
		.tv_sec = DEFERRED_PARK_US / 1000000,
		.tv_usec = DEFERRED_PARK_US % 1000000,
	};
	event_add(deferred_park_event, &tv);
}

static uint16_t port_effective_cap(const struct rss_autoscale_port_state *s) {
	uint16_t cap = (s->caps.allowed_count > 0) ?
		s->caps.allowed_n[s->caps.allowed_count - 1] :
		s->caps.max_n;
	if (s->policy_cap > 0 && s->policy_cap < cap)
		cap = s->policy_cap;
	return cap;
}

static uint16_t port_effective_floor(const struct rss_autoscale_port_state *s) {
	return s->policy_floor;
}

// Aggregate busy/total cycles of the workers serving at least one active queue
// of this port. Workers serving none are skipped; a worker shared between ports
// still contributes its cross-port cycles, so on shared-worker layouts this is
// the combined datapath utilisation, not a per-port figure -- a coarse "busy
// enough to keep the queues" signal for scale-down.
static void
port_worker_cycles(uint16_t port_id, uint16_t n_active, uint64_t *out_busy, uint64_t *out_total) {
	uint64_t busy = 0, total = 0;
	struct worker *w;
	STAILQ_FOREACH (w, &workers, next) {
		const struct worker_stats *ws = atomic_load_explicit(
			&w->stats, memory_order_relaxed
		);
		if (ws == NULL)
			continue;
		struct queue_map *qm;
		bool serves = false;
		vec_foreach_ref (qm, w->rxqs) {
			if (qm->port_id == port_id && qm->queue_id < n_active) {
				serves = true;
				break;
			}
		}
		if (!serves)
			continue;
		busy += ws->busy_cycles;
		total += ws->total_cycles;
	}
	*out_busy = busy;
	*out_total = total;
}

// Event-driven scale-up. The !any_idle guard blocks the elephant-flow
// ratchet (a single dominant 5-tuple keeps q0 saturated while newer
// queues never receive, so adding more queues never helps).
static uint16_t decide_port(struct rss_autoscale_port_state *s) {
	uint16_t cap = port_effective_cap(s);
	uint16_t floor = port_effective_floor(s);

	bool any_saturated = false;
	bool any_idle = false;
	uint16_t n_queues = (uint16_t)s->n_active;

	for (uint16_t q = 0; q < n_queues; q++) {
		struct rxq_health *h = &rxq_health[s->port_id][q];
		if (atomic_load_explicit(&h->saturated, memory_order_relaxed))
			any_saturated = true;
		if (atomic_load_explicit(&h->idle, memory_order_relaxed))
			any_idle = true;
	}

	uint16_t n_new = s->n_active;
	if (any_saturated && !any_idle) {
		uint16_t n_next = port_scale_caps_next(&s->caps, s->n_active);
		if (n_next > s->n_active)
			n_new = n_next;
	}

	s->n_load_recommended = n_new;

	// floor and cap are guaranteed to be in caps.allowed_n by API entry.
	if (floor > 0 && n_new < floor)
		n_new = floor;
	if (cap > 0 && n_new > cap)
		n_new = cap;

	return n_new;
}

// Per-port periodic scale-down. Steps n_active down when the aggregate
// busy/total of the workers serving the port has stayed below 40% over
// the last SCALE_DOWN_PERIOD_S window.
static void scale_down_timer_cb(evutil_socket_t /*fd*/, short /*what*/, void *arg) {
	struct rss_autoscale_port_state *s = arg;

	if (!s->caps.supports_scale)
		return;
	if (s->n_active <= 1)
		return;
	uint16_t floor = port_effective_floor(s);
	if (floor > 0 && s->n_active <= floor)
		return;

	// All active queues idle is a direct signal independent of cross-port
	// worker CPU attribution.
	bool all_idle = true;
	for (uint16_t q = 0; q < s->n_active; q++) {
		if (!atomic_load_explicit(&rxq_health[s->port_id][q].idle, memory_order_relaxed)) {
			all_idle = false;
			break;
		}
	}

	uint64_t busy_now, total_now;
	port_worker_cycles(s->port_id, s->n_active, &busy_now, &total_now);
	// worker_stats is replaced (counters reset to 0) on a graph reload; a
	// backwards step means that happened, so drop this window's deltas and
	// re-baseline. Avoids the uint64 underflow that would make d_busy * 10
	// overflow and the busy ratio meaningless.
	bool reloaded = busy_now < s->prev_busy_cycles || total_now < s->prev_total_cycles;
	uint64_t d_busy = reloaded ? 0 : busy_now - s->prev_busy_cycles;
	uint64_t d_total = reloaded ? 0 : total_now - s->prev_total_cycles;
	s->prev_busy_cycles = busy_now;
	s->prev_total_cycles = total_now;
	if (!all_idle) {
		if (d_total < 1000000)
			return; // not enough samples (startup race / post-reload)
		if (d_busy * 10 >= d_total * 4)
			return; // >= 40% busy
	}

	uint16_t n_load = port_scale_caps_prev(&s->caps, s->n_active);
	s->n_load_recommended = n_load;

	uint16_t n_new = n_load;
	if (floor > 0 && n_new < floor)
		n_new = floor;
	uint16_t cap = port_effective_cap(s);
	if (cap > 0 && n_new > cap)
		n_new = cap;
	if (n_new >= s->n_active)
		return;

	if (do_apply(s, n_new) == 0) {
		apply_unpark_all();
		schedule_deferred_park();
	}
}

static void rss_autoscale_decide_all(void);

static char rss_autoscale_kick_token;
static atomic_int rss_autoscale_kick_pending;

static void rss_autoscale_kick_cb(
	void * /*obj*/,
	uintptr_t /*priv*/,
	const struct control_queue_drain * /*drain*/
) {
	// Clear before scanning so a transition racing decide_all re-arms the
	// kick and is not lost.
	atomic_store_explicit(&rss_autoscale_kick_pending, 0, memory_order_relaxed);
	rss_autoscale_decide_all();
}

void rxq_health_notify_transition(void) {
	// Coalesce: at most one kick in flight. decide_all rescans every port,
	// so a single pass absorbs any number of concurrent transitions; this
	// keeps health edges from flooding the shared control queue and
	// starving the control-plane punt path.
	if (atomic_exchange_explicit(&rss_autoscale_kick_pending, 1, memory_order_relaxed) == 1)
		return;
	// Enqueue failure (control_queue full) is fine: clear the flag so any
	// later transition re-triggers a pass.
	if (control_queue_push(rss_autoscale_kick_cb, &rss_autoscale_kick_token, 0) == 0)
		control_queue_done();
	else
		atomic_store_explicit(&rss_autoscale_kick_pending, 0, memory_order_relaxed);
}

static void rss_autoscale_decide_all(void) {
	bool any_change = false;
	for (uint16_t port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		struct rss_autoscale_port_state *s = port_states[port_id];
		if (s == NULL || !s->caps.supports_scale)
			continue;
		uint16_t target = decide_port(s);
		if (target != s->n_active && do_apply(s, target) == 0)
			any_change = true;
	}
	if (any_change) {
		apply_unpark_all();
		schedule_deferred_park();
	}
}

int rss_autoscale_port_state_get(
	uint16_t port_id,
	uint16_t *n_active,
	uint16_t *n_load_recommended,
	uint16_t *cap,
	uint16_t *floor,
	uint16_t *max_n,
	uint16_t *min_n
) {
	struct rss_autoscale_port_state *s = state_get(port_id);
	if (s == NULL)
		return -ENODEV;
	if (!s->caps.supports_scale)
		return -ENOTSUP;
	if (n_active)
		*n_active = s->n_active;
	if (n_load_recommended)
		*n_load_recommended = s->n_load_recommended;
	if (cap)
		*cap = s->policy_cap;
	if (floor)
		*floor = s->policy_floor;
	// max_n / min_n are the usable bounds after cluster_size filtering,
	// not the raw HW range: an operator querying them must be able to
	// pass them back through set_cap / set_floor without -EINVAL.
	if (max_n)
		*max_n = (s->caps.allowed_count > 0) ?
			s->caps.allowed_n[s->caps.allowed_count - 1] :
			0;
	if (min_n)
		*min_n = (s->caps.allowed_count > 0) ? s->caps.allowed_n[0] : 0;
	return 0;
}

static void rss_autoscale_init(struct event_base *ev_base) {
	if (!gr_config.rss_autoscale)
		return;
	rss_autoscale_ev_base = ev_base;
	deferred_park_event = event_new(ev_base, -1, 0, deferred_park_cb, NULL);
	if (deferred_park_event == NULL)
		LOG(ERR, "rss-autoscale: failed to allocate deferred-park timer");
	LOG(NOTICE,
	    "rss-autoscale enabled: event-driven scale-up, "
	    "timer-driven scale-down (per-port, every %d s)",
	    SCALE_DOWN_PERIOD_S);

	event_subscribe(GR_EVENT_IFACE_POST_ADD, rss_autoscale_on_iface_post_add);
	event_subscribe(GR_EVENT_IFACE_REMOVE, rss_autoscale_on_iface_remove);
	event_subscribe(GR_EVENT_IFACE_POST_RECONFIG, rss_autoscale_on_iface_post_reconfig);
}

static void rss_autoscale_fini(struct event_base * /*ev_base*/) {
	if (deferred_park_event != NULL) {
		event_del(deferred_park_event);
		event_free(deferred_park_event);
		deferred_park_event = NULL;
	}
	rss_autoscale_ev_base = NULL;
	for (uint16_t i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (port_states[i] != NULL) {
			if (port_states[i]->scale_down_timer != NULL) {
				event_del(port_states[i]->scale_down_timer);
				event_free(port_states[i]->scale_down_timer);
				port_states[i]->scale_down_timer = NULL;
			}
			port_scale_caps_free(&port_states[i]->caps);
			free(port_states[i]);
			port_states[i] = NULL;
		}
	}
}

static struct module rss_autoscale_module = {
	.name = "rss_autoscale",
	.init = rss_autoscale_init,
	.fini = rss_autoscale_fini,
};

RTE_INIT(rss_autoscale_constructor) {
	module_register(&rss_autoscale_module);
}
