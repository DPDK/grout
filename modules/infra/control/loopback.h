// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Christophe Fontaine

#pragma once

struct iface_info_loopback {
	int fd;
	struct event *ev;
};
