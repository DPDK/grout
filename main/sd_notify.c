// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry
//
// This code is heavily inspired from:
// https://www.freedesktop.org/software/systemd/man/devel/sd_notify.html#Standalone%20Implementations

// SPDX-License-Identifier: MIT-0
//
// Implement the systemd notify protocol without external dependencies.
// Supports both readiness notification on startup and on reloading,
// according to the protocol defined at:
// https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
// This protocol is guaranteed to be stable as per:
// https://systemd.io/PORTABILITY_AND_STABILITY/

#include "sd_notify.h"

#include <gr_errno.h>

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void closefd(int *fd) {
	if (fd != NULL && *fd >= 0) {
		close(*fd);
		*fd = -1;
	}
}

int sd_notifyf(int unset_environment, const char *format, ...) {
	struct sockaddr_un sun = {.sun_family = AF_UNIX};
	__attribute__((cleanup(closefd))) int fd = -1;
	const char *sock_path;
	char msg[BUFSIZ];
	size_t msg_len;
	va_list ap;
	ssize_t n;

	// Verify the argument first
	if (format == NULL)
		return errno_set(EINVAL);

	va_start(ap, format);
	msg_len = vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);

	if (msg_len <= 0)
		return errno_set(EINVAL);

	// If the variable is not set, the protocol is a noop
	if ((sock_path = getenv("NOTIFY_SOCKET")) == NULL)
		return 0;

	// Only AF_UNIX is supported, with path or abstract sockets
	if (sock_path[0] != '/' && sock_path[0] != '@')
		return errno_set(EAFNOSUPPORT);

	// Ensure there is room for NUL byte
	if (strlen(sock_path) >= sizeof(sun.sun_path))
		return errno_set(E2BIG);

	memccpy(sun.sun_path, sock_path, 0, sizeof(sun.sun_path));

	// Support for abstract socket
	if (sun.sun_path[0] == '@')
		sun.sun_path[0] = 0;

	if ((fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)) < 0)
		return -errno;

	if (connect(fd, &sun, sizeof(sun)) != 0)
		return -errno;

	if ((n = write(fd, msg, msg_len)) != (ssize_t)msg_len)
		return errno_set(n < 0 ? errno : EPROTO);

	if (unset_environment != 0 && unsetenv("NOTIFY_SOCKET") < 0)
		return -errno;

	return 1; // Notified!
}
