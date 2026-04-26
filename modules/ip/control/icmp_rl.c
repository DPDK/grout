// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Farid Mihoub

#include "icmp_rl.h"

#include <gr_clock.h>

#include <stdint.h>
#include <time.h>

static struct time_space icmp_rl = {0};

void icmp_rl_init(uint32_t interval_ms) {
	icmp_rl.interval_ms = interval_ms;
	icmp_rl.last_ts = gr_clock_us();
}

bool icmp_rl_allow() {
	uint64_t now = gr_clock_us();

	if ((now - icmp_rl.last_ts) < (icmp_rl.interval_ms * 1000))
		return false;

	icmp_rl.last_ts = now;
	return true;
}
