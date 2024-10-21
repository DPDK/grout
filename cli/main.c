// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "complete.h"
#include "exec.h"
#include "interact.h"
#include "log.h"

#include <gr_api.h>
#include <gr_api_client_impl.h>
#include <gr_cli.h>

#include <ecoli.h>

#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <unistd.h>

// Please keep options/flags in alphabetical order.

static void usage(const char *prog) {
	printf("Usage: %s [-e] [-f PATH] [-h] [-s PATH] [-V] [-x] ...\n", prog);
	printf("       %s -c|--bash-complete\n", prog);
}

static void help(void) {
	puts("");
	printf("  Graph router CLI version %s.\n", GROUT_VERSION);
	puts("");
	puts("options:");
	puts("  -e, --err-exit             Abort on first error.");
	puts("  -f PATH, --file PATH       Read commands from file instead of stdin.");
	puts("  -h, --help                 Show this help message and exit.");
	puts("  -s PATH, --socket PATH     Path to the control plane API socket.");
	puts("                             Default: GROUT_SOCK_PATH from env or");
	printf("                             %s).\n", GR_DEFAULT_SOCK_PATH);
	puts("  -V, --version              Print version and exit.");
	puts("  -x, --trace-commands       Print executed commands.");
	puts("");
	puts("external completion:");
	puts("  -c, --bash-complete        For use in bash completion:");
	puts("                             complete -o default -C 'grcli -c' grcli");
}

struct gr_cli_opts {
	const char *sock_path;
	FILE *cmds_file;
	bool err_exit;
	bool trace_commands;
};

static struct gr_cli_opts opts;

static int parse_args(int argc, char **argv) {
	int c;

#define FLAGS ":ef:hs:Vx"
	static struct option long_options[] = {
		{"err-exit", no_argument, NULL, 'e'},
		{"file", required_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{"socket", required_argument, NULL, 's'},
		{"version", no_argument, NULL, 'V'},
		{"trace-commands", no_argument, NULL, 'x'},
		{0},
	};

	opterr = 0; // disable getopt default error reporting

	opts.sock_path = getenv("GROUT_SOCK_PATH");
	opts.cmds_file = stdin;

	while ((c = getopt_long(argc, argv, FLAGS, long_options, NULL)) != -1) {
		switch (c) {
		case 'e':
			opts.err_exit = true;
			break;
		case 'f':
			opts.cmds_file = fopen(optarg, "r+");
			if (opts.cmds_file == NULL) {
				errorf("--file %s: %s", optarg, strerror(errno));
				return -errno;
			}
			break;
		case 'h':
			usage(argv[0]);
			help();
			return -1;
		case 's':
			opts.sock_path = optarg;
			break;
		case 'V':
			printf("grcli %s\n", GROUT_VERSION);
			exit(EXIT_SUCCESS);
			break;
		case 'x':
			opts.trace_commands = true;
			break;
		case ':':
			usage(argv[0]);
			errorf("-%c requires a value", optopt);
			return errno_set(EINVAL);
		case '?':
			usage(argv[0]);
			errorf("-%c unknown option", optopt);
			return errno_set(EINVAL);
		default:
			usage(argv[0]);
			errorf("invalid arguments");
			return errno_set(EINVAL);
		}
	}

	if (opts.sock_path == NULL)
		opts.sock_path = GR_DEFAULT_SOCK_PATH;

	return optind;
}

int main(int argc, char **argv) {
	struct gr_api_client *client = NULL;
	struct ec_node *cmdlist = NULL;
	exec_status_t status;
	int ret, c;

	ret = EXIT_FAILURE;
	if (setlocale(LC_CTYPE, "C.UTF-8") == NULL) {
		perror("setlocale(LC_CTYPE, C.UTF-8)");
		goto end;
	}
	tty_init();

	if (ec_init() < 0) {
		errorf("ec_init: %s", strerror(errno));
		goto end;
	}

	if ((cmdlist = init_commands()) == NULL)
		goto end;

	if (argc >= 2 && (!strcmp(argv[1], "-c") || !strcmp(argv[1], "--bash-complete")))
		return bash_complete(cmdlist);

	if ((c = parse_args(argc, argv)) < 0)
		goto end;

	argc -= c;
	argv += c;

	if ((client = gr_api_client_connect(opts.sock_path)) == NULL) {
		errorf("gr_connect: %s", strerror(errno));
		goto end;
	}

	ec_dict_set(ec_node_attrs(cmdlist), CLIENT_ATTR, client, NULL);

	if (argc > 0) {
		status = exec_args(client, cmdlist, argc, (const char *const *)argv);
		if (print_cmd_status(status) < 0)
			goto end;
	} else if (is_tty(opts.cmds_file)) {
		if (interact(client, cmdlist) < 0)
			goto end;
	} else {
		char buf[BUFSIZ];
		while (fgets(buf, sizeof(buf), opts.cmds_file)) {
			if (opts.trace_commands)
				trace_cmd(buf);
			status = exec_line(client, cmdlist, buf);
			if (print_cmd_status(status) < 0 && opts.err_exit)
				goto end;
		}
	}

	ret = EXIT_SUCCESS;

end:
	if (gr_api_client_disconnect(client) < 0) {
		errorf("gr_disconnect: %s", strerror(errno));
		ret = EXIT_FAILURE;
	}
	ec_node_free(cmdlist);
	if (opts.cmds_file != NULL)
		fclose(opts.cmds_file);
	return ret;
}
