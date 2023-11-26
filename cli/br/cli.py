# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

import argparse
import copy
import os
import readline
import shlex


# ------------------------------------------------------------------------------
class Context:
    _ALL = []

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.commands = {}
        Context._ALL.append(self)

    def command(self, *args):
        def decorator(func):
            name = func.__name__.removeprefix(self.name + "_").replace("_", "-")
            self.commands[name] = {"func": func, "args": args}
            return func

        return decorator

    @classmethod
    def init_subparsers(cls, parser):
        sub = parser.add_subparsers(
            title="context help", metavar="CONTEXT", required=False
        )

        for ctx in cls._ALL:
            ctx_parser = sub.add_parser(
                ctx.name,
                description=ctx.description,
                help=ctx.description,
                add_help=False,
            )
            ctx_parser.add_argument("-h", "--help", action=ShowHelp)
            ctx_sub = ctx_parser.add_subparsers(
                title="sub-command help", metavar="SUB_COMMAND", required=True
            )
            for name, cmd in ctx.commands.items():
                cmd_parser = ctx_sub.add_parser(
                    name,
                    description=cmd["func"].__doc__,
                    help=cmd["func"].__doc__,
                    add_help=False,
                )
                cmd_parser.add_argument("-h", "--help", action=ShowHelp)
                for arg in cmd["args"]:
                    if len(arg.args) == 1 and "metavar" not in arg.kwargs:
                        arg.kwargs["metavar"] = arg.args[0].upper()
                    cmd_parser.add_argument(*arg.args, **arg.kwargs)
                cmd_parser.set_defaults(callback=cmd["func"])

        q = sub.add_parser(
            "quit",
            description="Exit the CLI",
            help="Exit the CLI",
            add_help=False,
        )
        q.set_defaults(callback=lambda *_: True)


# ------------------------------------------------------------------------------
class Arg:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


# ------------------------------------------------------------------------------
class ShowHelp(argparse.Action):
    def __init__(self, option_strings, *args, **kwargs):
        super().__init__(
            option_strings=option_strings,
            dest=argparse.SUPPRESS,
            default=argparse.SUPPRESS,
            nargs=0,
            help="show this help message",
        )

    def __call__(self, parser, namespace, values, option_string=None):
        raise HelpException(parser)


# ------------------------------------------------------------------------------
class HelpException(Exception):
    def __init__(self, parser):
        self.parser = parser

    def __str__(self):
        return self.parser.format_help()


# ------------------------------------------------------------------------------
class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        err = argparse.ArgumentError(None, message)
        err.parser = self
        raise err


# ------------------------------------------------------------------------------
class CLI:
    prompt = "br# "

    def __init__(self, client, parser):
        super().__init__()
        self._client = client
        self._parser = parser
        self._history_file = os.path.expanduser("~/.br_history")

    def interact(self):
        readline.read_init_file()
        readline.set_auto_history(True)
        readline.set_history_length(1000)
        try:
            readline.read_history_file(self._history_file)
        except FileNotFoundError:
            with open(self._history_file, "wb") as f:
                f.close()
        try:
            import argcomplete

            completer = argcomplete.CompletionFinder(
                copy.deepcopy(self._parser), default_completer=None
            )
            readline.set_completer_delims("")
            readline.set_completer(completer.rl_complete)
            readline.parse_and_bind("tab: complete")
        except ImportError:
            pass

        print("Welcome to the boring router interactive shell.")

        stop = False
        while not stop:
            try:
                line = input(self.prompt)
            except KeyboardInterrupt:
                print("^C")
                continue
            except EOFError:
                print("")
                break
            stop = self.run_command(line)

    def run_command(self, line, trace=False, err_exit=False):
        argv = shlex.split(line, comments=True)
        if not argv:
            return False
        if trace:
            print(f"+ {line.strip()}")
        try:
            args = self._parser.parse_args(argv)
        except HelpException as e:
            print(str(e))
            return False
        except argparse.ArgumentError as e:
            if err_exit:
                raise
            if hasattr(e, "parser"):
                e.parser.print_usage()  # pylint: disable=no-member
            print(f"error: {e}")
            return False

        if hasattr(args, "callback") and callable(args.callback):
            readline.append_history_file(1, self._history_file)
            try:
                return args.callback(self._client, self._parser, args)
            except OSError as e:
                if err_exit:
                    raise
                print(f"error: {e}")

        return False

    def complete_names(self, text, line, begidx, endidx):
        pass
