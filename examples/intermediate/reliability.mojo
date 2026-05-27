"""Reliability middleware — Retry[Inner] + TimeoutMiddleware[Inner].

Shows how to wrap a handler with two production-grade reliability
primitives:

- ``Retry[Inner]`` re-invokes the inner handler up to
  ``RetryPolicy.max_attempts`` times when it returns a 5xx
  response. Idempotent methods (GET / HEAD / PUT / DELETE /
  OPTIONS) retry by default; non-idempotent methods (POST /
  PATCH) are passed through once unless
  ``RetryPolicy.retry_only_idempotent`` is set to ``False``.

- ``TimeoutMiddleware[Inner]`` (exported as ``Timeout`` from the
  ``flare.http`` namespace; re-exported as
  ``TimeoutMiddleware`` from the top-level ``flare`` package to
  avoid colliding with ``flare.net.error.Timeout`` — the I/O
  timeout error type) bounds the inner handler's wall-clock
  time. If the budget is exhausted, the response is replaced
  with a sanitised 504 Gateway Timeout.

Pure construction — no live network. Run:

    pixi run example-reliability
"""

from flare.http import Handler, Request, Response
from flare.http.reliability import Retry, RetryPolicy, Timeout


@fieldwise_init
struct OkHandler(Copyable, Defaultable, Handler, Movable):
    """Always returns 200 OK — fast-path for both middlewares."""

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        resp.body = List[UInt8](String("hello").as_bytes())
        resp.headers.set("Content-Length", String(len(resp.body)))
        return resp^


@fieldwise_init
struct FlakyHandler(Copyable, Defaultable, Handler, Movable):
    """Always returns 503 — used to demonstrate retry exhaustion."""

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        return Response(status=503, reason=String("Service Unavailable"))


def main() raises:
    print("=== flare Example: Reliability middleware ===")
    print()

    # 1. Fast path through Retry: the inner returns 200 on the
    #    first attempt, so Retry never re-invokes it.
    var fast = Retry(
        OkHandler(),
        RetryPolicy(max_attempts=3, retry_only_idempotent=True),
    )
    var req = Request(method=String("GET"), url=String("/"))
    var resp = fast.serve(req)
    print("Retry / fast path  status:", resp.status)

    # 2. Retry exhausts max_attempts on a perpetually-flaky inner
    #    and surfaces the last 5xx. POSTs would *not* retry under
    #    the default policy; we flip retry_only_idempotent off to
    #    force a retry here just for illustration.
    var flaky = Retry(
        FlakyHandler(),
        RetryPolicy(max_attempts=2, retry_only_idempotent=False),
    )
    var resp2 = flaky.serve(req)
    print("Retry / exhausted   status:", resp2.status)

    # 3. Timeout disabled-by-zero-budget sentinel: a budget of 0
    #    ms is the explicit "no time allowed" knob — every call
    #    surfaces as a 504 without invoking the inner handler.
    var bounded = Timeout(OkHandler(), budget_ms=0)
    var resp3 = bounded.serve(req)
    print("Timeout / 0ms       status:", resp3.status)

    # 4. Timeout with a generous budget: the inner runs and the
    #    200 passes through unchanged.
    var bounded_ok = Timeout(OkHandler(), budget_ms=30_000)
    var resp4 = bounded_ok.serve(req)
    print("Timeout / 30s       status:", resp4.status)
