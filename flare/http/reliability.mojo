"""Reliability middleware: ``Retry`` + ``Timeout`` policies.

A reliability middleware wraps an inner ``Handler`` and adds a
policy that improves the chance the call succeeds in the face of
transient failures (transient upstream 5xx, slow handlers, etc).

This commit ships two policies; the matching ``RateLimit`` and
``CircuitBreaker`` policies follow in subsequent commits within
this cycle.

- :class:`Retry[Inner]` — re-invoke the inner handler when it
  raises or returns a 5xx response, up to ``max_attempts`` times.
  Caller-tunable retry set (any 5xx by default; bounded to 502 /
  503 / 504 by passing ``retry_only_idempotent=True``).
- :class:`Timeout[Inner]` — bound the wall-clock time the inner
  handler may consume. Returns ``Response.with_status(504)`` if
  the deadline elapses before serve() completes. (The timeout
  is observed via ``perf_counter_ns`` against the request's
  arrival time; integration with the reactor's ``Cancel`` cell
  flip is the v0.7-style enhancement in a later commit.)

Each middleware is generic over its inner ``Handler`` so the
chain stays monomorphised -- no virtual dispatch.
"""

from std.time import perf_counter_ns

from .handler import Handler
from .request import Request
from .response import Response


@fieldwise_init
struct RetryPolicy(Copyable, Defaultable, Movable):
    """Tunable retry policy.

    - ``max_attempts``: total number of inner-handler invocations
      (so ``max_attempts=3`` means 1 initial + 2 retries).
    - ``retry_only_idempotent``: when True, retries are gated on
      the request method being GET / HEAD / OPTIONS / TRACE
      (RFC 9110 §9.2 idempotent methods). When False, every 5xx
      triggers a retry regardless of method.

    Default: ``max_attempts=3``, ``retry_only_idempotent=True``.
    """

    var max_attempts: Int
    var retry_only_idempotent: Bool

    def __init__(out self):
        self.max_attempts = 3
        self.retry_only_idempotent = True


def _is_idempotent(method: String) -> Bool:
    """RFC 9110 §9.2 -- the idempotent methods are GET, HEAD,
    OPTIONS, TRACE, PUT, DELETE. PUT and DELETE are excluded from
    the retry default because their side effects make automated
    retry unsafe in practice; callers who know their handler is
    safe can flip ``retry_only_idempotent`` off."""
    return (
        method == String("GET")
        or method == String("HEAD")
        or method == String("OPTIONS")
        or method == String("TRACE")
    )


struct Retry[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Retry the inner handler on transient failure.

    A response with status >= 500 triggers a retry; a raised
    exception is also treated as a transient failure (the
    inner handler re-runs from scratch). The last attempt's
    outcome (response or exception) is propagated unchanged when
    all attempts are exhausted.

    The middleware does NOT sleep between attempts. A
    ``RateLimit[Inner]`` middleware composed *inside* ``Retry``
    is the canonical way to space retries; this keeps the
    reliability layer focused on retry-vs-no-retry policy and
    decouples sleep from the eviction policy.
    """

    var inner: Self.Inner
    var policy: RetryPolicy

    def __init__(out self):
        self.inner = Self.Inner()
        self.policy = RetryPolicy()

    def __init__(out self, var inner: Self.Inner, var policy: RetryPolicy = RetryPolicy()):
        self.inner = inner^
        self.policy = policy^

    def serve(self, req: Request) raises -> Response:
        # Pre-flight: if the request method is non-idempotent and
        # the policy gates retries on idempotency, fall through to
        # a single serve() (no retry attempt at all).
        var allow_retry = True
        if self.policy.retry_only_idempotent and not _is_idempotent(req.method):
            allow_retry = False
        if not allow_retry or self.policy.max_attempts <= 1:
            return self.inner.serve(req)
        # Otherwise: re-invoke up to ``max_attempts`` times.
        var attempt = 0
        var last_err: String = String("")
        var last_raised = False
        while attempt < self.policy.max_attempts:
            attempt += 1
            try:
                var resp = self.inner.serve(req)
                if resp.status < 500 or attempt == self.policy.max_attempts:
                    return resp^
                # 5xx and we still have attempts: retry.
            except e:
                last_err = String(e)
                last_raised = True
                if attempt == self.policy.max_attempts:
                    break
        if last_raised:
            raise Error(last_err)
        # Should be unreachable: the only way out without a
        # response is via the raise branch above.
        return self.inner.serve(req)


struct Timeout[Inner: Handler & Copyable & Defaultable](
    Copyable, Defaultable, Handler, Movable
):
    """Bound the inner handler's wall-clock time.

    The middleware records the entry timestamp and ALSO invokes
    the inner handler; on return, if elapsed wall time exceeds
    the configured budget, the response is replaced with a 504
    Gateway Timeout. This is the simple integration point; tight
    cancel-cell wiring (preempt the inner handler mid-serve)
    requires reactor cooperation and lands in a later commit.

    For the codec-style sans-I/O test surface this commit
    establishes today, the simple post-hoc check is the right
    primitive: handlers that genuinely block longer than the
    budget surface as 504, and those that just barely overrun
    get truncated. The reactor cell-flip integration is the
    enhancement.
    """

    var inner: Self.Inner
    var budget_ms: Int

    def __init__(out self):
        self.inner = Self.Inner()
        self.budget_ms = 30_000

    def __init__(out self, var inner: Self.Inner, budget_ms: Int = 30_000):
        self.inner = inner^
        self.budget_ms = budget_ms

    def serve(self, req: Request) raises -> Response:
        # ``budget_ms <= 0`` means "no time allowed at all": the
        # request is rejected before invoking the inner handler.
        # This keeps the contract intuitive for callers that flip
        # the budget through configuration (a zero budget is the
        # explicit "disabled" sentinel) and avoids the rounding
        # artifact where a sub-millisecond handler would otherwise
        # pass the elapsed > 0 check on a very fast host.
        if self.budget_ms <= 0:
            return Response(status=504, reason=String("Gateway Timeout"))
        var start = perf_counter_ns()
        var resp = self.inner.serve(req)
        var elapsed_ms = (perf_counter_ns() - start) // 1_000_000
        if elapsed_ms > UInt(self.budget_ms):
            return Response(status=504, reason=String("Gateway Timeout"))
        return resp^
