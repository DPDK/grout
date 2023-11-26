# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

"""
The boring router CLI.
"""

import argparse
import importlib
import pkgutil
import sys

import br
from br.c import Client
from br.cli import CLI, ArgumentParser, Context, HelpException, ShowHelp


def main():
    parser = ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("-h", "--help", action=ShowHelp)
    parser.add_argument(
        "-s",
        "--sock-path",
        default=Client.DEFAULT_SOCK_PATH,
        help="""
        API socket path (default: %(default)s).
        """,
    )
    parser.add_argument(
        "-e",
        "--err-exit",
        action="store_true",
        help="""
        Abort on first error.
        """,
    )
    parser.add_argument(
        "-x",
        "--trace-commands",
        action="store_true",
        help="""
        Print executed commands.
        """,
    )

    for _, mod, _ in pkgutil.iter_modules(br.__path__, prefix=br.__name__ + "."):
        importlib.import_module(mod)
    Context.init_subparsers(parser)

    try:
        args = parser.parse_args()
        client = Client(args.sock_path)
        cli = CLI(client, parser)

        if hasattr(args, "callback") and callable(args.callback):
            args.callback(client, parser, args)

        elif sys.stdin.isatty():
            cli.interact()

        else:
            for line in sys.stdin:
                cli.run_command(line, err_exit=args.err_exit, trace=args.trace_commands)

    except HelpException as e:
        print(str(e))
        sys.exit(1)

    except argparse.ArgumentError as e:
        if hasattr(e, "parser"):
            e.parser.print_usage(sys.stderr)  # pylint: disable=no-member
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
