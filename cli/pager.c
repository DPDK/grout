// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "log.h"
#include "pager.h"

#include <gr_cli.h>

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *pager_cmd = "less";
static int saved_stdout = -1;
static pid_t pager_pid = -1;
static bool disabled;

void pager_init(void) {
	const char *cmd;

	if (!is_tty(stdout)) {
		disabled = true;
		return;
	}

	cmd = getenv("GROUT_PAGER") ?: getenv("PAGER");
	if (cmd != NULL) {
		if (strlen(cmd) == 0) {
			disabled = true;
			return;
		}
		pager_cmd = cmd;
	}

	setenv("LESS", "-SFRXKe", 1);
	setenv("LESSSECURE", "1", 1);
}

void pager_disable(void) {
	disabled = true;
}

void pager_start(void) {
	int fds[2];

	if (disabled)
		return;

	if (pipe(fds) < 0) {
		errorf("pager: pipe(): %s", strerror(errno));
		return;
	}

	saved_stdout = dup(STDOUT_FILENO);
	if (saved_stdout < 0) {
		errorf("pager: dup(): %s", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		return;
	}
	pager_pid = fork();
	if (pager_pid < 0) {
		errorf("pager: fork(): %s", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		close(saved_stdout);
		saved_stdout = -1;
		return;
	}

	if (pager_pid == 0) {
		// Child: run pager reading from pipe.
		close(fds[1]);
		dup2(fds[0], STDIN_FILENO);
		close(fds[0]);
		execl("/bin/sh", "sh", "-c", pager_cmd, NULL);
		errorf("pager: execl(/bin/sh): %s", strerror(errno));
		// Use _exit() to avoid running atexit handlers and
		// flushing stdio buffers inherited from the parent.
		_exit(127);
	}

	// Parent: redirect stdout to pipe write end.
	close(fds[0]);
	dup2(fds[1], STDOUT_FILENO);
	close(fds[1]);

	// Ignore SIGPIPE in case the user quits the pager early.
	signal(SIGPIPE, SIG_IGN);
}

void pager_stop(void) {
	if (saved_stdout < 0)
		return;

	fflush(stdout);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdout);
	saved_stdout = -1;

	if (pager_pid > 0) {
		int status;
		waitpid(pager_pid, &status, 0);
		pager_pid = -1;
	}

	signal(SIGPIPE, SIG_DFL);
}
