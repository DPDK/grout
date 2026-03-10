// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "log.h"
#include "pager.h"

#include <gr_cli.h>

#include <fcntl.h>
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

static bool pager_check(const char *cmd) {
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		errorf("pager: fork(): %s", strerror(errno));
		return false;
	}
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR);
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		close(devnull);
		execl("/bin/sh", "sh", "-c", cmd, NULL);
		_exit(127);
	}
	waitpid(pid, &status, 0);
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

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

	setenv("LESS", "-SFRXK", 1);
	setenv("LESSSECURE", "1", 1);

	if (!pager_check(pager_cmd)) {
		errorf("pager disabled");
		disabled = true;
	}
}

void pager_disable(void) {
	disabled = true;
}

static void pager_start(void) {
	int fds[2];

	if (disabled)
		return;

	if (pipe(fds) < 0) {
		errorf("pager: pipe(): %s", strerror(errno));
		return;
	}

	// keep a reference on the tty before replacing stdout with the pager stdin
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

	// Ignore SIGPIPE and SIGCHLD in case the user quits the pager early.
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
}

static void pager_stop(void) {
	if (saved_stdout < 0)
		return;

	// force buffered output from printf() to be flushed to the pager stdin
	fflush(stdout);
	// restore stdout to point to tty
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdout);
	saved_stdout = -1;

	if (pager_pid > 0) {
		int status;
		waitpid(pager_pid, &status, 0);
		pager_pid = -1;
	}

	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
}

static struct cli_context ctx = {
	.name = "pager",
	.pre_cmd = pager_start,
	.post_cmd = pager_stop,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
