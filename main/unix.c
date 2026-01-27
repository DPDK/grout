// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Matej Mužila

#include "unix.h"

#include <gr_api.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_vec.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static gr_vec char **socket_paths;

static void unix_cleanup(struct event_base *) {
	gr_vec_foreach (char *path, socket_paths) {
		if (path != NULL)
			unlink(path);
	}

	gr_strvec_free(socket_paths);
}

#define SOCKET_LISTEN_BACKLOG 16
int unix_listen(const char *path) {
	union {
		struct sockaddr_un un;
		struct sockaddr a;
	} addr;
	int ret;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd == -1)
		return errno_log(errno, "socket");

	addr.un.sun_family = AF_UNIX;
	memccpy(addr.un.sun_path, path, 0, sizeof(addr.un.sun_path) - 1);

	ret = bind(fd, &addr.a, sizeof(addr.un));
	if (ret < 0 && errno == EADDRINUSE) {
		// unix socket file exists, check if there is a process
		// listening on the other side.
		ret = connect(fd, &addr.a, sizeof(addr.un));
		if (ret == 0) {
			LOG(ERR, "socket exists and is used %s", path);
			close(fd);
			return errno_set(EADDRINUSE);
		}
		if (ret < 0 && errno != ECONNREFUSED)
			return errno_log(errno, "connect");
		// remove socket file, and try to bind again
		if (unlink(addr.un.sun_path) < 0)
			return errno_log(errno, "unlink");
		ret = bind(fd, &addr.a, sizeof(addr.un));
	}
	if (ret < 0) {
		close(fd);
		return errno_log(errno, "bind");
	}

	gr_vec_add(socket_paths, strdup(path));

	if (listen(fd, SOCKET_LISTEN_BACKLOG) < 0) {
		close(fd);
		return errno_log(errno, "listen");
	}

	return fd;
}

static struct gr_module module = {
	.name = "unix",
	.init = NULL,
	.fini = unix_cleanup,
};

RTE_INIT(init) {
	gr_register_module(&module);
}
