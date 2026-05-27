"""Unit tests for the reliability middleware (Retry, Timeout)."""

from std.memory import UnsafePointer, alloc
from std.testing import assert_equal, assert_true

from flare.http.handler import Handler
from flare.http.reliability import (
    Retry,
    RetryPolicy,
    Timeout,
)
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok


# Shared counter cell so the Handler copies the reactor +
# middleware make during dispatch still record into one place.
# Each test allocates / frees its own cell so they stay
# independent.


struct AlwaysFiveHundredHandler(Copyable, Defaultable, Handler, Movable):
    """Always returns a 500; bumps a shared counter every call."""

    var calls_ptr: Int  # raw address; bitcast to UnsafePointer at use

    def __init__(out self):
        self.calls_ptr = 0

    def __init__(out self, ptr: Int):
        self.calls_ptr = ptr

    def serve(self, req: Request) raises -> Response:
        if self.calls_ptr != 0:
            var p = UnsafePointer[Int, MutExternalOrigin](
                unsafe_from_address=self.calls_ptr
            )
            p[] = p[] + 1
        return Response(status=500, reason=String("Internal Server Error"))


struct AlwaysOkHandler(Copyable, Defaultable, Handler, Movable):
    """Returns a fixed 200 OK response."""

    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        return ok(String("ok"))


struct EventuallyOkHandler(Copyable, Defaultable, Handler, Movable):
    """Returns 503 for the first ``fail_count`` calls, then 200."""

    var counter_ptr: Int
    var fail_count: Int

    def __init__(out self):
        self.counter_ptr = 0
        self.fail_count = 0

    def __init__(out self, ptr: Int, fail_count: Int):
        self.counter_ptr = ptr
        self.fail_count = fail_count

    def serve(self, req: Request) raises -> Response:
        if self.counter_ptr == 0:
            return ok(String("no-counter"))
        var p = UnsafePointer[Int, MutExternalOrigin](
            unsafe_from_address=self.counter_ptr
        )
        var n = p[]
        p[] = n + 1
        if n < self.fail_count:
            return Response(status=503, reason=String("Service Unavailable"))
        return ok(String("ok-after-failures"))


def _new_counter() -> Int:
    """Allocate a fresh shared Int cell and return its raw
    address. Caller must call ``_free_counter`` after the test."""
    var p = alloc[Int](1)
    p[] = 0
    return Int(p)


def _read_counter(addr: Int) -> Int:
    var p = UnsafePointer[Int, MutExternalOrigin](unsafe_from_address=addr)
    return p[]


def _free_counter(addr: Int):
    var p = UnsafePointer[Int, MutExternalOrigin](unsafe_from_address=addr)
    p.free()


def test_retry_succeeds_on_first_attempt() raises:
    """When the inner handler returns 200, Retry must not re-run
    it."""
    var addr = _new_counter()
    var inner = EventuallyOkHandler(ptr=addr, fail_count=0)
    var retry = Retry(
        inner^, RetryPolicy(max_attempts=3, retry_only_idempotent=True)
    )
    var req = Request(method=String("GET"), url=String("/"))
    var resp = retry.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(_read_counter(addr), 1)
    _free_counter(addr)


def test_retry_recovers_after_transient_failures() raises:
    """When the inner handler returns 503 twice then 200, Retry
    with max_attempts=3 must succeed on the third call."""
    var addr = _new_counter()
    var inner = EventuallyOkHandler(ptr=addr, fail_count=2)
    var retry = Retry(
        inner^, RetryPolicy(max_attempts=3, retry_only_idempotent=True)
    )
    var req = Request(method=String("GET"), url=String("/"))
    var resp = retry.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(_read_counter(addr), 3)
    _free_counter(addr)


def test_retry_gives_up_after_max_attempts() raises:
    """When the inner always returns 500, Retry exhausts
    max_attempts and surfaces the last 5xx."""
    var addr = _new_counter()
    var inner = AlwaysFiveHundredHandler(ptr=addr)
    var retry = Retry(
        inner^, RetryPolicy(max_attempts=3, retry_only_idempotent=True)
    )
    var req = Request(method=String("GET"), url=String("/"))
    var resp = retry.serve(req)
    assert_equal(resp.status, 500)
    assert_equal(_read_counter(addr), 3)
    _free_counter(addr)


def test_retry_skips_non_idempotent_methods_by_default() raises:
    """A POST request with the default ``retry_only_idempotent``
    policy must be invoked exactly once."""
    var addr = _new_counter()
    var inner = AlwaysFiveHundredHandler(ptr=addr)
    var retry = Retry(
        inner^, RetryPolicy(max_attempts=3, retry_only_idempotent=True)
    )
    var req = Request(method=String("POST"), url=String("/"))
    var resp = retry.serve(req)
    assert_equal(resp.status, 500)
    assert_equal(_read_counter(addr), 1)
    _free_counter(addr)


def test_retry_with_idempotent_off_retries_post() raises:
    """When ``retry_only_idempotent=False`` POSTs are also
    retried."""
    var addr = _new_counter()
    var inner = AlwaysFiveHundredHandler(ptr=addr)
    var retry = Retry(
        inner^,
        RetryPolicy(max_attempts=2, retry_only_idempotent=False),
    )
    var req = Request(method=String("POST"), url=String("/"))
    _ = retry.serve(req)
    assert_equal(_read_counter(addr), 2)
    _free_counter(addr)


def test_timeout_passes_through_fast_handler() raises:
    """A handler that returns within budget surfaces unchanged."""
    var inner = AlwaysOkHandler()
    var t = Timeout(inner^, budget_ms=5_000)
    var req = Request(method=String("GET"), url=String("/"))
    var resp = t.serve(req)
    assert_equal(resp.status, 200)


def test_timeout_returns_504_on_zero_budget() raises:
    """A 0ms budget is impossible to honour; any handler runtime
    > 0 ms surfaces as 504."""
    var inner = AlwaysOkHandler()
    var t = Timeout(inner^, budget_ms=0)
    var req = Request(method=String("GET"), url=String("/"))
    var resp = t.serve(req)
    # AlwaysOkHandler runs in some > 0 ns time, so the timeout
    # path triggers.
    assert_equal(resp.status, 504)


def main() raises:
    test_retry_succeeds_on_first_attempt()
    test_retry_recovers_after_transient_failures()
    test_retry_gives_up_after_max_attempts()
    test_retry_skips_non_idempotent_methods_by_default()
    test_retry_with_idempotent_off_retries_post()
    test_timeout_passes_through_fast_handler()
    test_timeout_returns_504_on_zero_budget()
    print("test_reliability: OK")
