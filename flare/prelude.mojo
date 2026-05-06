"""Curated re-export of the names everyday handler code reaches for.

A typical handler module in flare touches the same handful of names:
``Request``, ``Response``, ``Router``, ``HttpServer``, the ``Handler``
family (``Handler``, ``HandlerInfallible``, ``WithRaises``), the
``ok`` / ``ok_json`` / ``ok_json_value`` builders + the common 4xx/5xx
helpers, the ``Method`` / ``Status`` constants, and ``SocketAddr`` for
binding the listener. ``flare.prelude`` is the wildcard-importable
shortcut for that exact set, so the canonical import block shrinks
from 5–8 lines to one::

    from flare.prelude import *

    def hello(req: Request) -> Response:
        return ok("hello")

    def main() raises:
        var r = Router()
        r.get("/", hello)
        HttpServer.bind(SocketAddr.localhost(8080)).serve(r^, num_workers=4)

Domain-specific surfaces are deliberately *not* re-exported so the
prelude stays small enough that the import block of a real module
still documents which features it actually uses:

* Typed extractors (``PathInt``, ``QueryStr``, ``Form[T]``,
  ``Multipart``, ``Cookies``, ``Json[T]``, ``Extracted[H]``).
* Middleware (``Logger``, ``RequestId``, ``Compress``, ``CatchPanic``).
* ``Cors``, ``FileServer``, ``Conditional``, ``StaticResponse``.
* ``App[S]`` / ``State[T]``, ``Cancel`` / ``CancelHandler``,
  ``ViewHandler``, ``ComptimeRouter`` / ``ComptimeRoute``.
* Cookies, sessions, forms, multipart, SSE, content-encoding.
* Lower-level transports (``flare.tcp``, ``flare.tls``,
  ``flare.udp``, ``flare.dns``, ``flare.uds``, ``flare.runtime``,
  ``flare.http2``, ``flare.ws``).

For those, import the specific names from the matching module
(``flare.http``, ``flare.runtime``, ...). The prelude is the
"first ten lines of code" surface, not the kitchen sink.
"""

from .http.handler import Handler, HandlerInfallible, WithRaises
from .http.request import Method, Request
from .http.response import Response, Status
from .http.router import Router
from .http.server import (
    HttpServer,
    bad_request,
    internal_error,
    not_found,
    ok,
    ok_json,
    ok_json_value,
    redirect,
)
from .net.address import IpAddr, SocketAddr
