# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

import argparse
import re

import cffi


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o",
        "--output",
        required=True,
    )
    parser.add_argument(
        "sources",
        nargs="+",
        type=argparse.FileType("r", encoding="utf-8"),
    )
    args = parser.parse_args()

    ffi = cffi.FFI()

    includes = []
    for s in args.sources:
        ffi.cdef(sanitize_header(s.read()))
        includes.append(f"#include <{s.name}>")
    ffi.set_source("_br", "\n".join(includes))
    ffi.emit_c_code(args.output)


PREPROC_RE = re.compile(
    r"^#(if.*|ifdef.*|ifndef.*|endif.*|else.*|include.*|define \w+\(.*|define \w+)$",
    re.MULTILINE,
)

DEFINE_RE = re.compile(
    r"^#define (\w+) (.+)$",
    re.MULTILINE,
)


def define(match):
    name = match.group(1).strip()
    value = match.group(2).strip()
    if not value:
        return ""
    if value.startswith('"'):
        return f"extern char {name}[];"
    return f"#define {name} ..."


def sanitize_header(source: str) -> str:
    source = PREPROC_RE.sub("", source)
    source = DEFINE_RE.sub(define, source)
    return source


if __name__ == "__main__":
    main()
