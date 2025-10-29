// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy, Free Mobile

#pragma once

#include <linux/netlink.h>

void netlink_addattr(struct nlmsghdr *n, size_t maxlen, int type, const void *data, size_t alen);
struct rtattr *netlink_addattr_nest(struct nlmsghdr *n, size_t maxlen, int type);
void netlink_addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest);
int netlink_send_req(struct nlmsghdr *nlh);
