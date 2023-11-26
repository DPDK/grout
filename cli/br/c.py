# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Robin Jarry

import os
import typing as T

from _br import ffi, lib


# ------------------------------------------------------------------------------
def str2c(s: T.Optional[str]) -> "char *":
    if s is None:
        return ffi.NULL
    if hasattr(s, "encode"):
        s = s.encode("utf-8")
    return ffi.new("char []", s)


# ------------------------------------------------------------------------------
def c2str(c: "char *") -> T.Optional[str]:
    if c == ffi.NULL:
        return None
    s = ffi.string(c)
    if hasattr(s, "decode"):
        s = s.decode("utf-8")
    return s


# ------------------------------------------------------------------------------
def mac2str(c: "struct br_ether_addr *") -> T.Optional[str]:
    if c == ffi.NULL:
        return None
    return ":".join(f"{c.bytes[i]:02x}" for i in range(6))


# ------------------------------------------------------------------------------
class Client:
    DEFAULT_SOCK_PATH = c2str(lib.BR_DEFAULT_SOCK_PATH)

    def __init__(self, sock_path: str = DEFAULT_SOCK_PATH):
        cdata = lib.br_connect(str2c(sock_path))
        if cdata == ffi.NULL:
            raise self.error()
        self.cdata = ffi.gc(cdata, lib.br_disconnect)

    def error(self, message: str = None) -> OSError:
        return OSError(ffi.errno, os.strerror(ffi.errno), message)

    not_found = object()

    def __getattr__(self, name: str) -> T.Any:
        try:
            attr = getattr(lib, name)
            wrapped = False
        except AttributeError:
            attr = getattr(lib, "br_" + name, self.not_found)
            if attr is self.not_found:
                raise
            wrapped = True

        if wrapped and callable(attr) and not isinstance(attr, ffi.CData):

            def wrap(*args):
                if attr(self.cdata, *args):
                    raise self.error()

            return wrap
        return attr
