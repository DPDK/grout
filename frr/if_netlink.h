// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

struct zebra_ns;
void netlink_add_dummy_link(struct zebra_ns *zns, const char *ifname);
