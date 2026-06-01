"""Per-connection state machine + byte-fast-path helpers for the
reactor-backed HTTP server.

This module owns:

* The ``STATE_*`` integer constants and the ``StepResult`` return shape.
* ``ConnHandle`` -- the per-connection state machine that walks each
  connection through ``STATE_READING`` -> ``STATE_WRITING`` ->
  ``STATE_CLOSING`` driven by readable / writable / timeout events
  from the reactor.
* The local h2c-upgrade detector + the byte-fast-path / keep-alive
  helpers (``_monotonic_ms``, the ``Connection`` header predicates,
  the ``_compact_read_buf_drop_prefix`` memcpy, the case-insensitive
  matchers used by the response serializer).

The sister module ``flare/http/_server_reactor_impl.mojo`` owns the
I/O-bearing pieces -- reactor entry-point loops, ``Pool[ConnHandle]``
allocation glue, io_uring buffer-ring scaffolding -- and re-exports
every public symbol below for back-compat with existing imports
across ``flare/http/``, ``flare/http2/``, ``flare/runtime/``, tests,
and the fuzz corpus.

State transitions::

    STATE_READING ─ handler returned ─> STATE_WRITING ─ flushed ─┬─> STATE_READING (keep-alive)
                                                                └─> STATE_CLOSING (should_close)
    STATE_READING / STATE_WRITING ─ peer close / error / timeout ─> STATE_CLOSING

# TODO(track-reactor-split): this file is allowlisted in
# tools/check_reactor_size.sh because it currently exceeds the 600-
# line cap the reactor sub-package wants to enforce. The natural
# seams to extract next:
#
#   _reactor/keepalive_scan.mojo  -- ``Connection`` header
#       predicates + ``_compact_read_buf_drop_prefix`` + case-
#       insensitive byte matchers (independent of ``ConnHandle``).
#   _reactor/h1_dispatch.mojo     -- the H1 read / parse / handler
#       call path on ``ConnHandle.on_readable`` (bulk of the file).
#   _reactor/write_path.mojo      -- the response serializer + the
#       ``StepResult`` driver consumed by ``on_writable``.
#
# Each split is mechanical (pure code motion, no behaviour change)
# and lands in its own atomic commit so the diff stays
# review-friendly. After the splits land the allowlist entry comes
# off and the lint enforces the 600-line cap with no escape hatch.
"""

from std.collections import List, Optional
from std.ffi import c_int, c_size_t, external_call, get_errno, ErrNo
from std.memory import memcpy, stack_allocation

from flare.crypto.hmac import base64url_decode
from flare.http.cancel import CancelCell, CancelReason
from flare.http.handler import Handler, CancelHandler, ViewHandler
from flare.http.headers import HeaderMap
from flare.http.proto.h2c_upgrade import (
    detect_h2c_upgrade as _proto_detect_h2c_upgrade,
)
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import (
    ServerConfig,
    _find_crlfcrlf,
    _scan_content_length,
    _parse_http_request_bytes,
    _parse_http_request_bytes_minimal,
    _ascii_lower,
    _status_reason,
    _append_str,
    _append_int,
)
from flare.http.static_response import StaticResponse
from flare.net import SocketAddr
from flare.net._libc import _recv, _send, MSG_NOSIGNAL
from flare.tcp import TcpStream
from flare.runtime import DateCache


# ── State constants ───────────────────────────────────────────────────────────

comptime STATE_READING: Int = 0
"""Reading headers and body from the socket (non-blocking)."""

comptime STATE_WRITING: Int = 1
"""Writing the response back to the socket (non-blocking)."""

comptime STATE_CLOSING: Int = 2
"""Connection is shutting down; next event should finalize close."""


# ── h2c upgrade detection ─────────────────────────────────────────────


@always_inline
def _detect_h2c_upgrade_inline(headers: HeaderMap) -> Bool:
    """Thin wrapper around :func:`flare.http.proto.h2c_upgrade.detect_h2c_upgrade`.

    The neutral sans-I/O detector lives in
    :mod:`flare.http.proto.h2c_upgrade`; the canonical helper in
    :mod:`flare.http2.server` also delegates there. This wrapper
    keeps the local call site short (the `_inline` name signals
    "predicate over a parsed HeaderMap" at the per-conn dispatch
    point) and avoids pulling :mod:`flare.http2.server` into the
    reactor's import graph.
    """
    return _proto_detect_h2c_upgrade(headers)


# ── Step result ───────────────────────────────────────────────────────────────


struct StepResult(Copyable, ImplicitlyCopyable, Movable):
    """Outcome of one state-machine step.

    The reactor wrapper uses these fields to update its registration for
    the connection's fd (interest bits), decide whether the connection is
    finished, and arm / clear the idle timer.

    Fields:
        want_read: True if the fd should be watched for readability.
        want_write: True if the fd should be watched for writability.
        done: True if the connection is finished; caller should unregister
              the fd and close it.
        idle_timeout_ms: -1 = no change; 0 = clear any pending idle timer;
                        > 0 = arm a fresh idle timer for this many
                        milliseconds.
        h2c_upgrade: True when the connection has just finished writing
                     a ``101 Switching Protocols`` response and the unified
                     reactor must migrate this fd's conn-dict entry from
                     ``KIND_H1`` to ``KIND_H2`` (RFC 7540 §3.2). The
                     migration helper extracts the saved Request +
                     decoded ``HTTP2-Settings`` payload from the h1
                     ``ConnHandle`` and constructs an
                     :class:`H2ConnHandle` pre-seeded with the original
                     request as stream id 1.
    """

    var want_read: Bool
    var want_write: Bool
    var done: Bool
    var idle_timeout_ms: Int
    var h2c_upgrade: Bool

    def __init__(
        out self,
        want_read: Bool = False,
        want_write: Bool = False,
        done: Bool = False,
        idle_timeout_ms: Int = -1,
        h2c_upgrade: Bool = False,
    ):
        """Construct a StepResult.

        Args:
            want_read: Whether the caller should keep read interest on the fd.
            want_write: Whether the caller should add write interest.
            done: Whether the caller should unregister and close the fd.
            idle_timeout_ms: Idle-timer rearm instruction (-1 = unchanged,
                0 = clear, >0 = arm for this many ms).
            h2c_upgrade: True when the unified reactor should migrate
                this fd from ``KIND_H1`` to ``KIND_H2`` after the 101
                Switching Protocols response has been flushed.
        """
        self.want_read = want_read
        self.want_write = want_write
        self.done = done
        self.idle_timeout_ms = idle_timeout_ms
        self.h2c_upgrade = h2c_upgrade


# ── Monotonic clock + small ASCII helpers ─────────────────────────────────────


def _monotonic_ms() -> Int:
    """Return the monotonic clock in milliseconds.

    Uses ``clock_gettime(CLOCK_MONOTONIC, ...)``. The constant value 1 for
    ``CLOCK_MONOTONIC`` is portable between Linux and macOS (macOS has
    supported it since 10.12).
    """
    var buf = stack_allocation[16, UInt8]()
    for i in range(16):
        (buf + i).init_pointee_copy(UInt8(0))
    _ = external_call["clock_gettime", c_int](c_int(1), buf.bitcast[NoneType]())
    var sec: Int64 = 0
    var nsec: Int64 = 0
    for i in range(8):
        sec |= Int64(Int((buf + i).load())) << Int64(8 * i)
    for i in range(8):
        nsec |= Int64(Int((buf + 8 + i).load())) << Int64(8 * i)
    return Int(sec) * 1000 + Int(nsec) // 1_000_000


@always_inline
def _is_content_length(k: String) -> Bool:
    """Return True if ``k`` is ``Content-Length`` (ASCII case-insensitive).

    Hot path: called for every response header to decide whether
    ``_serialize_response`` should emit or skip. Avoids the lowercase
    allocation that ``_ascii_lower`` + string-compare would cost.
    """
    if k.byte_length() != 14:
        return False
    var p = k.unsafe_ptr()
    var target = "content-length"
    var t = target.unsafe_ptr()
    for i in range(14):
        var c = p[i]
        if c >= 65 and c <= 90:
            c = c + 32
        if c != t[i]:
            return False
    return True


@always_inline
def _is_date(k: String) -> Bool:
    """Return True if ``k`` is ``Date`` (ASCII case-insensitive).

    Hot path: called for every response header during serialise so
    that any caller-supplied ``Date`` is dropped in favour of the
    canonical IMF-fixdate emitted from the per-connection
    :class:`DateCache`. RFC 9110 §6.6.1 mandates a single ``Date``
    field-line; the cached form is always correct, the
    caller-supplied one might drift.
    """
    if k.byte_length() != 4:
        return False
    var p = k.unsafe_ptr()
    var target = "date"
    var t = target.unsafe_ptr()
    for i in range(4):
        var c = p[i]
        if c >= 65 and c <= 90:
            c = c + 32
        if c != t[i]:
            return False
    return True


@always_inline
def _connection_is_keepalive(s: String) -> Bool:
    """Hot-path byte fast-check for ``Connection: keep-alive``.

    Designed to short-circuit the per-request ``_ascii_lower`` +
    string-compare in the keep-alive policy decision. wrk2 / wrk /
    `curl --keepalive` / nearly every Rust HTTP client send the
    header value as the exact bytes ``keep-alive`` (lowercase,
    no leading whitespace). This helper matches that exact-bytes
    case in 10 byte loads + 10 compares without any allocation.

    For non-matching values (uppercase, mixed-case, ``Keep-Alive``
    with capital K, header missing, etc.) callers fall back to
    the slow path (``_ascii_lower(s) == "keep-alive"``).

    Returns False on length mismatch or any byte mismatch.
    """
    if s.byte_length() != 10:
        return False
    var p = s.unsafe_ptr()
    return (
        p[0] == UInt8(ord("k"))
        and p[1] == UInt8(ord("e"))
        and p[2] == UInt8(ord("e"))
        and p[3] == UInt8(ord("p"))
        and p[4] == UInt8(ord("-"))
        and p[5] == UInt8(ord("a"))
        and p[6] == UInt8(ord("l"))
        and p[7] == UInt8(ord("i"))
        and p[8] == UInt8(ord("v"))
        and p[9] == UInt8(ord("e"))
    )


@always_inline
def _connection_is_close(s: String) -> Bool:
    """Hot-path byte fast-check for ``Connection: close``.

    Companion to :func:`_connection_is_keepalive`. Matches the exact
    lowercase bytes ``close`` in 5 byte loads, and as a small
    extension also matches the common mixed-case ``Close`` (capital
    C only). Anything else falls through to the slow ``_ascii_lower``
    path. Returns False on length mismatch.
    """
    if s.byte_length() != 5:
        return False
    var p = s.unsafe_ptr()
    var c0 = p[0]
    if c0 != UInt8(ord("c")) and c0 != UInt8(ord("C")):
        return False
    return (
        p[1] == UInt8(ord("l"))
        and p[2] == UInt8(ord("o"))
        and p[3] == UInt8(ord("s"))
        and p[4] == UInt8(ord("e"))
    )


@always_inline
def _compact_read_buf_drop_prefix(
    mut read_buf: List[UInt8], drop_n: Int
) -> None:
    """Drop the first ``drop_n`` bytes of ``read_buf``, keeping the
    trailing bytes (typically: pipelined-next-request bytes that
    arrived in the same recv as the just-handled request).

    Hot path: called once per processed request from every
    on_readable_* state-machine entry point AND from the static
    fast path. Replaces the prior 5 inlined ``for i in range(...)
    leftover.append(...)`` byte loops which did O(N) per-byte
    appends + bounds-checks; this version uses a single
    ``memcpy`` from the old buffer into a freshly-sized
    replacement, preserving the prior allocation pattern (still
    one List[UInt8] alloc per request) while collapsing the
    per-byte append loop.

    Pre-conditions enforced by the callers:
    * ``drop_n > 0`` -- if no bytes to drop, callers skip this
      helper.
    * ``drop_n <= len(read_buf)`` -- otherwise the math below
      under-flows.
    """
    var n = len(read_buf)
    if drop_n >= n:
        # Either exactly consumed (drop_n == n) or over-consumed
        # (defensive). Either way the buffer is empty after this.
        read_buf.clear()
        return
    var keep = n - drop_n
    # Non-overlapping memcpy from old buffer into a fresh
    # capacity-sized List. The old buffer's drop is implicit when
    # we move the new one into ``read_buf`` (the caller's previous
    # storage drops at scope-end). This matches the prior shape
    # (one List alloc per request, prior bytes freed after) but
    # replaces the O(N) per-byte append loop with a single memcpy.
    var leftover = List[UInt8](capacity=keep)
    leftover.resize(keep, UInt8(0))
    memcpy(
        dest=leftover.unsafe_ptr(),
        src=read_buf.unsafe_ptr() + drop_n,
        count=keep,
    )
    read_buf = leftover^


# ── HTTP/1.1 keep-alive policy ────────────────────────────────────────────────


@always_inline
def _compute_close_after(req_headers: HeaderMap, req_version: String) -> Bool:
    """Decide whether to close the connection after this request,
    based on RFC 9112 keep-alive policy.

    Hot path: called once per request from every on_readable_*
    state-machine entry point. The byte-fast-paths for
    ``Connection: keep-alive`` and ``Connection: close`` short-
    circuit the per-request ``_ascii_lower`` allocation when the
    header value matches the wrk2 / curl / nearly-every-Rust-
    client lowercase wire format. Mixed-case + uncommon values
    fall through to the slow allocation path.

    Caller still needs to combine this with config.max_keepalive_-
    requests + config.keep_alive (those are per-server policy, not
    per-request).
    """
    # Imported lazily to keep this module's top-level import block
    # free of ``flare.http.server`` -- the helper only fires on the
    # mixed-case slow path so the deferred import never bites the
    # hot-path lowercase branch.
    from flare.http.server import _ascii_lower

    var conn_hdr = req_headers.get("connection")
    var is_http10 = req_version == "HTTP/1.0"
    if _connection_is_close(conn_hdr):
        return True
    if _connection_is_keepalive(conn_hdr):
        return False
    if conn_hdr.byte_length() == 0:
        # No Connection header. RFC 9112: HTTP/1.1 is keep-alive
        # by default; HTTP/1.0 is close by default.
        return is_http10
    # Slow path: lowercase + compare. Reachable on mixed-case
    # ``Keep-Alive`` etc.
    var lo = _ascii_lower(conn_hdr)
    if lo == "close":
        return True
    if is_http10 and lo != "keep-alive":
        return True
    return False


def _wants_close(data: List[UInt8], header_end: Int) -> Bool:
    """Scan the raw header block for HTTP/1.0 + ``Connection:`` signals
    that mean this connection should close after the response.

    Returns True when the request line declares HTTP/1.0 without a
    ``Connection: keep-alive`` override, or when any ``Connection:``
    header value equals ``close`` (case-insensitive).

    Operates directly on bytes so the static fast path doesn't need to
    construct a ``Request`` / ``HeaderMap``.
    """
    var n = header_end
    var version_is_10 = False
    # 1. Request line up to the first CRLF.
    var first_eol = -1
    for i in range(n):
        if data[i] == 10:  # LF
            first_eol = i
            break
    if first_eol < 0:
        first_eol = n
    # Look for "HTTP/1.0" on the request line.
    var http_needle = "HTTP/1.0"
    var hp = http_needle.unsafe_ptr()
    var hn = http_needle.byte_length()
    for i in range(first_eol - hn + 1):
        if i < 0:
            break
        var is_match = True
        for j in range(hn):
            if data[i + j] != hp[j]:
                is_match = False
                break
        if is_match:
            version_is_10 = True
            break
    # 2. Connection header. Case-insensitive name match, value compared
    # against "close" and "keep-alive" (lowercase).
    var needle = "connection:"
    var np = needle.unsafe_ptr()
    var nn = needle.byte_length()
    var conn_close = False
    var conn_keepalive = False
    var i = first_eol + 1
    while i < n - nn:
        var found = True
        for j in range(nn):
            var c = data[i + j]
            if c >= 65 and c <= 90:
                c = c + 32
            if c != np[j]:
                found = False
                break
        if found:
            var pos = i + nn
            while pos < n and (data[pos] == 32 or data[pos] == 9):
                pos += 1
            # Compare value until CR, LF, or end-of-header-block.
            var v_end = pos
            while v_end < n and data[v_end] != 13 and data[v_end] != 10:
                v_end += 1
            # Lowercase slice compare against "close" and "keep-alive".
            var val_len = v_end - pos
            if val_len == 5:
                var ck = True
                for j in range(5):
                    var c = data[pos + j]
                    if c >= 65 and c <= 90:
                        c = c + 32
                    if c != UInt8(ord("close"[j])):
                        ck = False
                        break
                if ck:
                    conn_close = True
            if val_len == 10:
                var ck2 = True
                for j in range(10):
                    var c = data[pos + j]
                    if c >= 65 and c <= 90:
                        c = c + 32
                    if c != UInt8(ord("keep-alive"[j])):
                        ck2 = False
                        break
                if ck2:
                    conn_keepalive = True
            break
        i += 1
    if conn_close:
        return True
    if version_is_10 and not conn_keepalive:
        return True
    return False


@always_inline
def _is_connection(k: String) -> Bool:
    """Return True if ``k`` is ``Connection`` (ASCII case-insensitive)."""
    if k.byte_length() != 10:
        return False
    var p = k.unsafe_ptr()
    var target = "connection"
    var t = target.unsafe_ptr()
    for i in range(10):
        var c = p[i]
        if c >= 65 and c <= 90:
            c = c + 32
        if c != t[i]:
            return False
    return True


# ── Connection handle ─────────────────────────────────────────────────────────


struct ConnHandle(Movable):
    """State + buffers for a single reactor-managed HTTP connection.

    **Takes ownership** of the accepted ``TcpStream`` (which owns the
    socket's fd). The stream is moved into ``_stream`` at construction
    and closed on destruction. This avoids the ASAP-destruction hazard
    that arises from passing just an ``Int32`` fd: Mojo's ownership
    model would drop the originating ``TcpStream`` as soon as its last
    explicit reference went out of scope, closing the fd out from under
    the reactor.
    """

    var _stream: TcpStream
    """Underlying connection; this struct is the sole owner. ``self.fd``
    is a fast accessor for ``self._stream._socket.fd``."""
    var peer: SocketAddr
    """Kernel-reported peer address captured from
    ``TcpStream.peer_addr()`` at construction time. Threaded into every
    parsed ``Request`` for the connection so handlers can read
    ``req.peer``. Stored here (not just on each ``Request``) because
    keep-alive connections re-parse multiple requests across a single
    ``ConnHandle`` lifetime, and the peer is identical for all of them."""
    var cancel_cell: CancelCell
    """Per-connection cancel cell. The reactor flips
    its ``Int`` to a non-zero ``CancelReason`` on peer FIN, deadline
    (commit 5), or drain (commit 6); ``on_readable_cancel`` hands a
    ``Cancel`` handle bound to this cell into
    ``CancelHandler.serve(req, cancel)``. Reset between pipelined
    requests so a cancel reason on one request doesn't leak into
    the next."""
    var state: Int
    var read_buf: List[UInt8]
    """Incoming request bytes accumulated across partial reads."""
    var headers_end: Int
    """Byte offset just past the ``\\r\\n\\r\\n`` header terminator; -1
    while headers are still being read."""
    var content_length: Int
    """Value of the Content-Length header for the current request."""
    var body_total: Int
    """Total bytes needed to have the full request: headers_end + content_length.
    """
    var write_buf: List[UInt8]
    """Serialised response bytes; drained by successive send calls."""
    var write_pos: Int
    """Number of bytes of ``write_buf`` already sent."""
    var keepalive_count: Int
    """Number of requests already served on this keep-alive connection."""
    var idle_timer_id: UInt64
    """ID of the currently-armed idle timer, 0 if none. The caller (reactor
    wrapper) manages the actual TimerWheel entry."""
    var should_close: Bool
    """True once we've decided this connection must close after writing."""
    var last_interest: Int
    """Last reactor interest bits for this conn. Used by the orchestrator
    to skip redundant ``reactor.modify`` syscalls when the wanted interest
    hasn't actually changed since the previous event."""
    var send_in_flight: Bool
    """``True`` iff a ``IORING_OP_SEND`` SQE for this conn's
    ``write_buf`` has been submitted but the corresponding CQE
    hasn't been observed yet. Set to True by the io_uring
    buffer-ring + submit_send dispatch after each ``submit_send``,
    and back to False when the matching ``URING_OP_SEND`` CQE
    arrives. While True, recv CQEs for this conn are buffered
    into ``read_buf`` but NOT parsed -- the next request can't
    be processed until the in-flight ``write_buf`` has been
    released by the kernel. Always ``False`` on the epoll path
    (which does synchronous send + frees write_buf in
    ``on_writable``)."""

    var _h2c_upgrade_pending: Bool
    """``True`` iff this h1 connection has received a valid
    ``Upgrade: h2c`` request (RFC 7540 §3.2), queued the
    ``101 Switching Protocols`` response into ``write_buf``, and
    is now waiting for that response to flush before the unified
    reactor migrates the conn-dict entry from ``KIND_H1`` to
    ``KIND_H2``. The accompanying :attr:`_h2c_upgrade_request`
    and :attr:`_h2c_upgrade_settings` fields hold the migration
    payload."""
    var _h2c_upgrade_request: Optional[Request]
    """The original h1 request that triggered the h2c upgrade.
    The unified reactor's migration helper consumes this to seed
    stream id 1 on the new :class:`H2ConnHandle`."""
    var _h2c_upgrade_settings: List[UInt8]
    """Base64url-decoded raw bytes of the inbound ``HTTP2-Settings``
    header (a SETTINGS frame body per RFC 7540 §3.2.1). Applied
    to the new HTTP/2 connection state during migration."""

    var _date_cache: DateCache
    """Per-connection cached ``Date:`` header (RFC 9110 §6.6.1).

    Closes critique register §C2 (DateCache existed but was never
    plumbed into the response writer): we now emit ``Date:`` on
    every response and amortise the formatting cost via the
    cache's once-per-second rule. The ``clock_gettime`` call on
    Linux x86_64 is vDSO-fast (no syscall), and the 29-byte
    formatter only runs when the wall-clock second has rolled
    over since the previous response on this connection."""

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def __init__(
        out self, var stream: TcpStream, read_buffer_size: Int = 8192
    ) raises:
        """Construct a ConnHandle that owns ``stream`` in STATE_READING.

        Args:
            stream: Accepted ``TcpStream`` (non-blocking mode must already
                be set by the caller). Ownership transfers into the
                ``ConnHandle``.
            read_buffer_size: Initial capacity for the read buffer.
        """
        # Capture the peer address before moving the stream — ``peer_addr``
        # reads from the stream's internal field, which becomes
        # inaccessible once we transfer ownership into ``self._stream``.
        self.peer = stream.peer_addr()
        self._stream = stream^
        self.cancel_cell = CancelCell()
        self.state = STATE_READING
        self.read_buf = List[UInt8](capacity=read_buffer_size)
        self.headers_end = -1
        self.content_length = 0
        self.body_total = -1
        self.write_buf = List[UInt8]()
        self.write_pos = 0
        self.keepalive_count = 0
        self.idle_timer_id = UInt64(0)
        self.should_close = False
        # Accept registers with INTEREST_READ only.
        self.last_interest = 1  # INTEREST_READ
        self.send_in_flight = False
        self._h2c_upgrade_pending = False
        self._h2c_upgrade_request = Optional[Request]()
        self._h2c_upgrade_settings = List[UInt8]()
        self._date_cache = DateCache()

    @always_inline
    def fd(self) -> c_int:
        """Return the underlying fd. Fast accessor; does not check state."""
        return self._stream._socket.fd

    # ── Event handlers ────────────────────────────────────────────────────────

    def on_readable[
        H: Handler
    ](mut self, ref handler: H, config: ServerConfig,) raises -> StepResult:
        """Drive the state machine on a readable event.

        Consumes as much as the non-blocking socket makes available per
        call. Transitions to ``STATE_WRITING`` when the full request is
        parsed and the handler has returned.

        Args:
            handler: Request -> Response callback.
            config: Server configuration (limits + timeouts).

        Returns:
            A ``StepResult`` describing the new reactor-interest state.
        """
        if self.state != STATE_READING:
            # Spurious readable on a connection we've already moved past
            # reading — tell the caller to stop reading.
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        # Drain the socket until EAGAIN. Bulk-copy each chunk into
        # ``read_buf`` via resize + in-place memcpy rather than per-byte
        # append; the latter was a measurable hot-path cost at
        # 100K+ req/s.
        var chunk = stack_allocation[8192, UInt8]()
        while True:
            var got = _recv(self.fd(), chunk, c_size_t(8192), c_int(0))
            if got > 0:
                var old_len = len(self.read_buf)
                var got_int = Int(got)
                self.read_buf.resize(old_len + got_int, UInt8(0))
                var dst = self.read_buf.unsafe_ptr() + old_len
                # memcpy is substantially faster than a per-byte load/store
                # loop here because ``chunk`` is stack-allocated and
                # contiguous, and the copy is always <= 8KiB.
                memcpy(dest=dst, src=chunk, count=got_int)
                if (
                    len(self.read_buf)
                    > config.max_header_size + config.max_body_size
                ):
                    self._queue_error(413, "Content Too Large")
                    return self._transition_to_writing()
            elif got == 0:
                # Peer closed while we were still reading — half-open.
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                # Hard read error — close the connection.
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)

        # See if we have enough to parse.
        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
                # Still accumulating headers.
                if len(self.read_buf) > config.max_header_size:
                    self._queue_error(431, "Request Header Fields Too Large")
                    return self._transition_to_writing()
                return StepResult(
                    want_read=True,
                    want_write=False,
                    idle_timeout_ms=config.idle_timeout_ms,
                )
            self.headers_end = end
            self.content_length = _scan_content_length(
                self.read_buf, self.headers_end
            )
            if self.content_length > config.max_body_size:
                self._queue_error(413, "Content Too Large")
                return self._transition_to_writing()
            self.body_total = self.headers_end + self.content_length

        # Body not fully read yet?
        if len(self.read_buf) < self.body_total:
            return StepResult(
                want_read=True,
                want_write=False,
                idle_timeout_ms=config.idle_timeout_ms,
            )

        # Parse the request. When
        # ``ServerConfig.skip_header_decode_for_short_requests``
        # is set, use the minimal parser that skips HeaderMap
        # construction. The Connection-policy decision then uses
        # _wants_close on the raw header bytes (already in
        # self.read_buf) instead of the per-request
        # _ascii_lower(req.headers.get(...)).
        var req: Request
        var close_after: Bool
        try:
            if config.skip_header_decode_for_short_requests:
                req = _parse_http_request_bytes_minimal(
                    Span[UInt8, _](self.read_buf)[: self.body_total],
                    self.headers_end,
                    self.content_length,
                    config.max_body_size,
                    config.max_uri_length,
                    self.peer,
                    config.expose_error_messages,
                )
                # Raw-bytes Connection-policy decision: scan the
                # header block bytes without HeaderMap allocation.
                # _wants_close handles HTTP/1.0 default-close +
                # explicit Connection: close (case-insensitive).
                close_after = _wants_close(self.read_buf, self.headers_end)
            else:
                req = _parse_http_request_bytes(
                    Span[UInt8, _](self.read_buf)[: self.body_total],
                    config.max_header_size,
                    config.max_body_size,
                    config.max_uri_length,
                    self.peer,
                    config.expose_error_messages,
                )
                close_after = _compute_close_after(req.headers, req.version)
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        # h2c upgrade detection (RFC 7540 §3.2). Hot-path-aware: 99.99 %
        # of inbound requests don't carry ``Upgrade: h2c`` so we
        # short-circuit on the first cheap header lookup -- a single
        # ``HeaderMap.get("upgrade")`` returning the empty string skips
        # the entire upgrade-handling branch (no ``Optional[T]``
        # allocation, no base64url decode, no further function calls).
        # Only the ~one-in-a-million genuine h2c request takes the cold
        # path that hands off to ``_h2c_upgrade_decode_settings``.
        if req.headers.get("upgrade").byte_length() != 0:
            var settings_payload: Optional[List[UInt8]]
            try:
                settings_payload = self._h2c_upgrade_decode_settings(
                    req.headers
                )
            except:
                settings_payload = Optional[List[UInt8]]()
            if settings_payload:
                self._start_h2c_upgrade(req^, settings_payload.value().copy())
                # Compact the read buffer so subsequent bytes
                # (the client's h2 connection preface) start at offset 0.
                if self.body_total > 0 and self.body_total <= len(
                    self.read_buf
                ):
                    _compact_read_buf_drop_prefix(
                        self.read_buf, self.body_total
                    )
                self.headers_end = -1
                self.content_length = 0
                self.body_total = -1
                self.state = STATE_WRITING
                return StepResult(
                    want_read=False,
                    want_write=True,
                    idle_timeout_ms=0,
                )

        self.keepalive_count += 1
        if self.keepalive_count >= config.max_keepalive_requests:
            close_after = True
        if not config.keep_alive:
            close_after = True
        self.should_close = close_after

        # Call the handler. Exceptions are caught and converted to 500.
        var resp: Response
        try:
            resp = handler.serve(req^)
        except:
            self._queue_error(500, "Internal Server Error")
            return self._transition_to_writing()

        # Compact the read buffer: drop the processed request, keep the
        # remainder (pipelining or prefetched next request).
        if self.body_total > 0 and self.body_total <= len(self.read_buf):
            _compact_read_buf_drop_prefix(self.read_buf, self.body_total)
        self.headers_end = -1
        self.content_length = 0
        self.body_total = -1

        self._serialize_response(resp^, not close_after)
        return self._transition_to_writing()

    def on_readable_from_buf[
        H: Handler
    ](
        mut self,
        bytes: Span[UInt8, _],
        ref handler: H,
        config: ServerConfig,
    ) raises -> StepResult:
        """``on_readable[H]`` variant for the io_uring recv-multishot
        path: takes pre-recv'd bytes from a kernel-delivered buffer
        instead of looping on ``_recv()`` itself.

        The caller (``run_uring_recv_reactor_loop``) gets the bytes
        from a ``URING_OP_RECV`` CQE (the kernel placed them in the
        per-conn buffer at SQE-submit time). We append them to
        ``read_buf`` and run the same header-scan / parse / handler
        / serialise / keep-alive bookkeeping as ``on_readable[H]``
        does after its drain-until-EAGAIN loop. The per-conn state
        machine is otherwise identical -- the only delta vs the
        epoll path is the source of bytes (kernel push vs userspace
        recv pull).

        The ``IORING_OP_RECV`` CQE with ``res == 0`` (peer closed)
        is handled by the caller, not here -- this method only
        runs when there are real bytes to feed.

        Args:
            bytes: New bytes to feed into the read pipeline. May be
                empty (legitimate when the kernel re-issues a
                multishot completion immediately after re-arm; we
                skip the parse step in that case).
            handler: Request -> Response callback.
            config: Server configuration.

        Returns:
            A ``StepResult`` describing the new reactor-interest
            state. ``done=True`` means the connection should be
            cleaned up.
        """
        if self.state != STATE_READING:
            # Spurious recv on a connection that already moved past
            # reading -- mirror on_readable's no-op shape.
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        if len(bytes) > 0:
            var old_len = len(self.read_buf)
            var add = len(bytes)
            self.read_buf.resize(old_len + add, UInt8(0))
            var dst = self.read_buf.unsafe_ptr() + old_len
            memcpy(dest=dst, src=bytes.unsafe_ptr(), count=add)
            if (
                len(self.read_buf)
                > config.max_header_size + config.max_body_size
            ):
                self._queue_error(413, "Content Too Large")
                return self._transition_to_writing()

        # Header completion check (mirror on_readable lines after the
        # recv loop).
        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
                if len(self.read_buf) > config.max_header_size:
                    self._queue_error(431, "Request Header Fields Too Large")
                    return self._transition_to_writing()
                return StepResult(
                    want_read=True,
                    want_write=False,
                    idle_timeout_ms=config.idle_timeout_ms,
                )
            self.headers_end = end
            self.content_length = _scan_content_length(
                self.read_buf, self.headers_end
            )
            if self.content_length > config.max_body_size:
                self._queue_error(413, "Content Too Large")
                return self._transition_to_writing()
            self.body_total = self.headers_end + self.content_length

        if len(self.read_buf) < self.body_total:
            return StepResult(
                want_read=True,
                want_write=False,
                idle_timeout_ms=config.idle_timeout_ms,
            )

        # Same parser fast-path as on_readable; opt-in via the
        # same config bit. Drops per-request HeaderMap alloc in
        # the bufring path too.
        var req: Request
        var close_after: Bool
        try:
            if config.skip_header_decode_for_short_requests:
                req = _parse_http_request_bytes_minimal(
                    Span[UInt8, _](self.read_buf)[: self.body_total],
                    self.headers_end,
                    self.content_length,
                    config.max_body_size,
                    config.max_uri_length,
                    self.peer,
                    config.expose_error_messages,
                )
                close_after = _wants_close(self.read_buf, self.headers_end)
            else:
                req = _parse_http_request_bytes(
                    Span[UInt8, _](self.read_buf)[: self.body_total],
                    config.max_header_size,
                    config.max_body_size,
                    config.max_uri_length,
                    self.peer,
                    config.expose_error_messages,
                )
                close_after = _compute_close_after(req.headers, req.version)
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        self.keepalive_count += 1
        if self.keepalive_count >= config.max_keepalive_requests:
            close_after = True
        if not config.keep_alive:
            close_after = True
        self.should_close = close_after

        var resp: Response
        try:
            resp = handler.serve(req^)
        except:
            self._queue_error(500, "Internal Server Error")
            return self._transition_to_writing()

        if self.body_total > 0 and self.body_total <= len(self.read_buf):
            _compact_read_buf_drop_prefix(self.read_buf, self.body_total)
        self.headers_end = -1
        self.content_length = 0
        self.body_total = -1

        self._serialize_response(resp^, not close_after)
        return self._transition_to_writing()

    def on_readable_cancel[
        CH: CancelHandler
    ](mut self, ref handler: CH, config: ServerConfig,) raises -> StepResult:
        """Cancel-aware variant of ``on_readable``.

        Identical to ``on_readable`` except the per-connection
        ``CancelCell`` is reset to ``NONE`` at the top of each
        request, flipped to ``PEER_CLOSED`` on ``recv == 0``
        observed before the handler runs, and a ``Cancel`` handle
        bound to the cell is passed to ``CH.serve(req, cancel)``.

        Future commits in hook deadline (commit 5) and
        drain (commit 6) flips through the same cell.
        """
        if self.state != STATE_READING:
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        # Reset the cancel cell at the start of each request so a
        # cancellation observed on a previous pipelined request does
        # not leak into this one. Idempotent on the first request of
        # a connection because the cell is already ``NONE`` from
        # construction.
        self.cancel_cell.reset()

        var chunk = stack_allocation[8192, UInt8]()
        while True:
            var got = _recv(self.fd(), chunk, c_size_t(8192), c_int(0))
            if got > 0:
                var old_len = len(self.read_buf)
                var got_int = Int(got)
                self.read_buf.resize(old_len + got_int, UInt8(0))
                var dst = self.read_buf.unsafe_ptr() + old_len
                memcpy(dest=dst, src=chunk, count=got_int)
                if (
                    len(self.read_buf)
                    > config.max_header_size + config.max_body_size
                ):
                    self._queue_error(413, "Content Too Large")
                    return self._transition_to_writing()
            elif got == 0:
                # Peer closed while we were still reading — flip
                # cancel for any cancel-aware code that runs after
                # this point in the loop, then mark the connection
                # for shutdown.
                self.cancel_cell.flip(CancelReason.PEER_CLOSED)
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)

        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
                if len(self.read_buf) > config.max_header_size:
                    self._queue_error(431, "Request Header Fields Too Large")
                    return self._transition_to_writing()
                return StepResult(
                    want_read=True,
                    want_write=False,
                    idle_timeout_ms=config.idle_timeout_ms,
                )
            self.headers_end = end
            self.content_length = _scan_content_length(
                self.read_buf, self.headers_end
            )
            if self.content_length > config.max_body_size:
                self._queue_error(413, "Content Too Large")
                return self._transition_to_writing()
            self.body_total = self.headers_end + self.content_length

        if len(self.read_buf) < self.body_total:
            # Body still arriving — arm the read-body deadline if
            # configured, otherwise fall back to
            # the idle timer. Closes the slow-body-upload variant
            # of criticism §2.2: a peer that keeps trickling bytes
            # below idle_timeout_ms can no longer hold a worker
            # slot indefinitely.
            var body_timeout = (
                config.read_body_timeout_ms if config.read_body_timeout_ms
                > 0 else config.idle_timeout_ms
            )
            return StepResult(
                want_read=True,
                want_write=False,
                idle_timeout_ms=body_timeout,
            )

        # follow-up (Track 1.1 / C2): scan the request as a
        # ``RequestView`` borrowed into ``read_buf`` first, then
        # materialise an owned ``Request`` via ``into_owned()``
        # for the existing ``Handler.serve(req: Request)`` shape.
        # Net win: per-header String allocation eliminated during
        # parse — headers stay as offsets into the shared buffer
        # until ``into_owned`` copies them out. Body still copies
        # because today's Handler takes an owned Request; the
        # zero-copy body path waits for C3 (``ViewHandler``).
        from flare.http.request_view import parse_request_view

        var req: Request
        try:
            var view = parse_request_view(
                Span[UInt8, _](self.read_buf)[: self.body_total],
                config.max_header_size,
                config.max_body_size,
                config.max_uri_length,
                self.peer,
                config.expose_error_messages,
            )
            req = view.into_owned()
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        var close_after = _compute_close_after(req.headers, req.version)

        self.keepalive_count += 1
        if self.keepalive_count >= config.max_keepalive_requests:
            close_after = True
        if not config.keep_alive:
            close_after = True
        self.should_close = close_after

        var resp: Response
        try:
            # Hand the handler a cancel handle bound to this
            # connection's cancel cell. The cell outlives the handler
            # call (it's owned by ``self``).
            resp = handler.serve(req^, self.cancel_cell.handle())
        except:
            self._queue_error(500, "Internal Server Error")
            return self._transition_to_writing()

        if self.body_total > 0 and self.body_total <= len(self.read_buf):
            _compact_read_buf_drop_prefix(self.read_buf, self.body_total)
        self.headers_end = -1
        self.content_length = 0
        self.body_total = -1

        self._serialize_response(resp^, not close_after)
        return self._transition_to_writing()

    def on_readable_view[
        VH: ViewHandler
    ](mut self, ref handler: VH, config: ServerConfig) raises -> StepResult:
        """View-aware variant of ``on_readable_cancel``.

        Same control flow as ``on_readable_cancel`` but dispatches
        the parsed ``RequestView`` directly into
        ``VH.serve_view(view, cancel)`` — the body slice borrows
        from ``self.read_buf`` and the handler reads it without
        a copy. The owned ``Request`` materialisation that the
        ``Handler.serve`` requires is skipped entirely.

        Net win on this path: handler gets ``Span[UInt8, origin]``
        body access — the headline zero-copy upload contract from
        design-0.5 §1.1.
        """
        if self.state != STATE_READING:
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        self.cancel_cell.reset()

        var chunk = stack_allocation[8192, UInt8]()
        while True:
            var got = _recv(self.fd(), chunk, c_size_t(8192), c_int(0))
            if got > 0:
                var old_len = len(self.read_buf)
                var got_int = Int(got)
                self.read_buf.resize(old_len + got_int, UInt8(0))
                var dst = self.read_buf.unsafe_ptr() + old_len
                memcpy(dest=dst, src=chunk, count=got_int)
                if (
                    len(self.read_buf)
                    > config.max_header_size + config.max_body_size
                ):
                    self._queue_error(413, "Content Too Large")
                    return self._transition_to_writing()
            elif got == 0:
                self.cancel_cell.flip(CancelReason.PEER_CLOSED)
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)

        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
                if len(self.read_buf) > config.max_header_size:
                    self._queue_error(431, "Request Header Fields Too Large")
                    return self._transition_to_writing()
                return StepResult(
                    want_read=True,
                    want_write=False,
                    idle_timeout_ms=config.idle_timeout_ms,
                )
            self.headers_end = end
            self.content_length = _scan_content_length(
                self.read_buf, self.headers_end
            )
            if self.content_length > config.max_body_size:
                self._queue_error(413, "Content Too Large")
                return self._transition_to_writing()
            self.body_total = self.headers_end + self.content_length

        if len(self.read_buf) < self.body_total:
            var body_timeout = (
                config.read_body_timeout_ms if config.read_body_timeout_ms
                > 0 else config.idle_timeout_ms
            )
            return StepResult(
                want_read=True,
                want_write=False,
                idle_timeout_ms=body_timeout,
            )

        # Parse the request as a borrowed view into ``read_buf``
        # and dispatch it directly. Body is ``Span[UInt8, origin]``
        # for the duration of the ``serve_view`` call.
        from flare.http.request_view import parse_request_view

        var resp: Response
        try:
            var view = parse_request_view(
                Span[UInt8, _](self.read_buf)[: self.body_total],
                config.max_header_size,
                config.max_body_size,
                config.max_uri_length,
                self.peer,
                config.expose_error_messages,
            )

            # Connection-disposition from the borrowed header
            # view — no allocation, just an offsets-based lookup.
            var hv = view.headers()
            var conn_hdr = _ascii_lower(String(hv.get("connection")))
            var is_http10 = view.version == "HTTP/1.0"
            var close_after = False
            if conn_hdr == "close":
                close_after = True
            elif is_http10 and conn_hdr != "keep-alive":
                close_after = True

            self.keepalive_count += 1
            if self.keepalive_count >= config.max_keepalive_requests:
                close_after = True
            if not config.keep_alive:
                close_after = True
            self.should_close = close_after

            try:
                resp = handler.serve_view(view, self.cancel_cell.handle())
            except:
                self._queue_error(500, "Internal Server Error")
                return self._transition_to_writing()
        except:
            self._queue_error(400, "Bad Request")
            return self._transition_to_writing()

        if self.body_total > 0 and self.body_total <= len(self.read_buf):
            _compact_read_buf_drop_prefix(self.read_buf, self.body_total)
        self.headers_end = -1
        self.content_length = 0
        self.body_total = -1

        var keepalive = not self.should_close
        self._serialize_response(resp^, keepalive)
        return self._transition_to_writing()

    def on_readable_static(
        mut self, resp: StaticResponse, config: ServerConfig
    ) raises -> StepResult:
        """Static-response variant of ``on_readable``.

        Reads as much as the non-blocking socket makes available per
        call, scans for the end-of-headers marker, discards the
        declared body bytes (if any), and queues the pre-encoded
        ``StaticResponse`` bytes into ``write_buf``. The parser never
        constructs a ``Request``; no handler is called.

        Everything else (keep-alive book-keeping, HTTP/1.0 close
        semantics, ``max_keepalive_requests`` cap, Connection header
        inspection, peer-close / EAGAIN handling, pipelined-request
        compaction of ``read_buf``) mirrors ``on_readable`` byte-for-byte
        so state machine invariants remain identical.
        """
        if self.state != STATE_READING:
            return StepResult(
                want_read=False, want_write=self.state == STATE_WRITING
            )

        var chunk = stack_allocation[8192, UInt8]()
        while True:
            var got = _recv(self.fd(), chunk, c_size_t(8192), c_int(0))
            if got > 0:
                var old_len = len(self.read_buf)
                var got_int = Int(got)
                self.read_buf.resize(old_len + got_int, UInt8(0))
                var dst = self.read_buf.unsafe_ptr() + old_len
                memcpy(dest=dst, src=chunk, count=got_int)
                if (
                    len(self.read_buf)
                    > config.max_header_size + config.max_body_size
                ):
                    self._queue_error(413, "Content Too Large")
                    return self._transition_to_writing()
            elif got == 0:
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)

        # Headers still incomplete?
        if self.headers_end < 0:
            var end = _find_crlfcrlf(self.read_buf, 0)
            if end < 0:
                if len(self.read_buf) > config.max_header_size:
                    self._queue_error(431, "Request Header Fields Too Large")
                    return self._transition_to_writing()
                return StepResult(
                    want_read=True,
                    want_write=False,
                    idle_timeout_ms=config.idle_timeout_ms,
                )
            self.headers_end = end
            self.content_length = _scan_content_length(
                self.read_buf, self.headers_end
            )
            if self.content_length > config.max_body_size:
                self._queue_error(413, "Content Too Large")
                return self._transition_to_writing()
            self.body_total = self.headers_end + self.content_length

        # Body still incomplete?
        if len(self.read_buf) < self.body_total:
            return StepResult(
                want_read=True,
                want_write=False,
                idle_timeout_ms=config.idle_timeout_ms,
            )

        # Inspect Connection header + HTTP/1.0 semantics on the raw
        # header bytes without building a Request object. Cheap scan
        # over the header region only.
        var close_after = _wants_close(self.read_buf, self.headers_end)
        self.keepalive_count += 1
        if self.keepalive_count >= config.max_keepalive_requests:
            close_after = True
        if not config.keep_alive:
            close_after = True
        self.should_close = close_after

        # Compact read buffer before writing the canned response.
        if self.body_total > 0 and self.body_total <= len(self.read_buf):
            _compact_read_buf_drop_prefix(self.read_buf, self.body_total)
        self.headers_end = -1
        self.content_length = 0
        self.body_total = -1

        self._serialize_static(resp, not close_after)
        return self._transition_to_writing()

    def on_writable(mut self, config: ServerConfig) raises -> StepResult:
        """Drive the state machine on a writable event.

        Sends as much of ``write_buf`` as the non-blocking socket accepts.
        When the buffer is fully flushed, transitions back to
        ``STATE_READING`` (keep-alive) or ``STATE_CLOSING`` based on
        ``should_close``.

        Args:
            config: Server configuration (used to compute the new idle timer
                after a successful flush).

        Returns:
            A ``StepResult`` describing the new reactor-interest state.
        """
        if self.state != STATE_WRITING:
            return StepResult(
                want_read=self.state == STATE_READING, want_write=False
            )

        while self.write_pos < len(self.write_buf):
            var remaining = len(self.write_buf) - self.write_pos
            var ptr = self.write_buf.unsafe_ptr() + self.write_pos
            var n = _send(
                self.fd(), ptr, c_size_t(remaining), c_int(MSG_NOSIGNAL)
            )
            if n > 0:
                self.write_pos += Int(n)
            else:
                var e = get_errno()
                if e == ErrNo.EINTR:
                    continue
                if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                    break
                # Hard write error — close.
                self.should_close = True
                return StepResult(want_read=False, want_write=False, done=True)

        if self.write_pos < len(self.write_buf):
            # Partial write — re-arm on writable.
            return StepResult(
                want_read=False,
                want_write=True,
                idle_timeout_ms=config.write_timeout_ms,
            )

        # Response fully sent.
        self.write_buf.clear()
        self.write_pos = 0

        # h2c upgrade migration cue: the 101 Switching Protocols response
        # has just flushed. Tell the unified reactor to swap the conn-dict
        # entry from KIND_H1 to KIND_H2 (seeded with the saved request +
        # decoded HTTP2-Settings payload). The reactor reads the
        # migration data via :meth:`take_h2c_upgrade_payload` before
        # freeing this h1 ConnHandle.
        if self._h2c_upgrade_pending:
            return StepResult(
                want_read=False,
                want_write=False,
                done=False,
                idle_timeout_ms=0,
                h2c_upgrade=True,
            )

        if self.should_close:
            return StepResult(want_read=False, want_write=False, done=True)

        # Keep-alive: back to reading, possibly on already-buffered next
        # request (pipelining — data may already be in read_buf).
        self.state = STATE_READING
        return StepResult(
            want_read=True,
            want_write=False,
            idle_timeout_ms=config.idle_timeout_ms,
        )

    def take_h2c_upgrade_request(mut self) raises -> Request:
        """Move the saved h2c upgrade ``Request`` out of this handle.

        Called by ``_unified_reactor_impl._migrate_h1_to_h2`` after
        ``on_writable`` returns ``StepResult(h2c_upgrade=True)``.
        Companion to :meth:`take_h2c_upgrade_settings` -- callers
        invoke both to extract the migration payload before freeing
        the h1 handle. Setting the in-flight flag to ``False`` here
        is deferred to :meth:`take_h2c_upgrade_settings` so a partial
        ``take_request`` doesn't silently leave the settings buffer
        behind.
        """
        if not self._h2c_upgrade_pending:
            raise Error("take_h2c_upgrade_request: not pending")
        if not self._h2c_upgrade_request:
            raise Error("take_h2c_upgrade_request: payload missing")
        return self._h2c_upgrade_request.take()

    def take_h2c_upgrade_settings(mut self) -> List[UInt8]:
        """Move the saved decoded ``HTTP2-Settings`` payload out
        of this handle. Resets the in-flight flag so a subsequent
        migration attempt raises rather than silently re-using the
        same buffer.
        """
        var settings = self._h2c_upgrade_settings^
        self._h2c_upgrade_settings = List[UInt8]()
        self._h2c_upgrade_pending = False
        return settings^

    def on_timeout(mut self) -> StepResult:
        """Handle an idle / write timer firing.

        Returns a StepResult with ``done=True``. The caller should
        unregister and close the fd.
        """
        self.state = STATE_CLOSING
        self.should_close = True
        return StepResult(want_read=False, want_write=False, done=True)

    def close(mut self) -> None:
        """Explicitly close the underlying stream. Idempotent.

        Normally the caller does not need to call this: the stream's
        destructor closes the fd when the ``ConnHandle`` is dropped.
        """
        self._stream.close()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _transition_to_writing(mut self) -> StepResult:
        """Move into STATE_WRITING and tell the caller to watch for write."""
        self.state = STATE_WRITING
        # Reset any stale read state: the next state-machine step is
        # flushing the response, not reading more bytes.
        return StepResult(
            want_read=False,
            want_write=True,
            # Clear the idle timer; the write_timeout (if any) arms
            # separately via StepResult idle_timeout_ms on the first
            # writable step.
            idle_timeout_ms=0,
        )

    def _h2c_upgrade_decode_settings(
        self, headers: HeaderMap
    ) raises -> Optional[List[UInt8]]:
        """Inspect a parsed h1 request's headers and return the decoded
        ``HTTP2-Settings`` payload iff this is a valid h2c upgrade.

        Returns ``None`` when:

        * The request lacks ``Upgrade: h2c`` + ``HTTP2-Settings``.
        * The ``HTTP2-Settings`` value isn't valid base64url.
        * The decoded payload's length isn't a multiple of 6 (an
          ill-formed SETTINGS body per RFC 7540 §3.2.1).

        Caller falls through to the normal handler path on ``None``.
        """
        if not _detect_h2c_upgrade_inline(headers):
            return Optional[List[UInt8]]()
        var s = headers.get("http2-settings")
        if s.byte_length() == 0:
            return Optional[List[UInt8]]()
        var decoded: List[UInt8]
        try:
            decoded = base64url_decode(s)
        except:
            return Optional[List[UInt8]]()
        if (len(decoded) % 6) != 0:
            return Optional[List[UInt8]]()
        return Optional[List[UInt8]](decoded^)

    def _start_h2c_upgrade(
        mut self, var req: Request, var settings_payload: List[UInt8]
    ) -> None:
        """Save the migration payload + queue the ``101 Switching Protocols``
        response. Caller must have already verified the upgrade is valid via
        :meth:`_h2c_upgrade_decode_settings`."""
        self._h2c_upgrade_settings = settings_payload^
        self._h2c_upgrade_request = Optional[Request](req^)
        self._h2c_upgrade_pending = True

        # Queue the 101 Switching Protocols response (RFC 7540 §3.2).
        # ``Connection: close`` is intentionally OMITTED so the same
        # TCP fd carries the subsequent HTTP/2 frames.
        self.write_buf.clear()
        self.write_pos = 0
        var wire = self.write_buf^
        _append_str(wire, "HTTP/1.1 101 Switching Protocols\r\n")
        _append_str(wire, "Connection: Upgrade\r\n")
        _append_str(wire, "Upgrade: h2c\r\n\r\n")
        self.write_buf = wire^

    def _queue_error(mut self, status: Int, reason: String) -> None:
        """Build a minimal error response into ``write_buf`` and mark close."""
        self.should_close = True
        var body_str = String(status) + " " + reason
        var resp = Response(status=status, reason=reason)
        var body_bytes = body_str.as_bytes()
        for i in range(len(body_bytes)):
            resp.body.append(body_bytes[i])
        try:
            resp.headers.set("Content-Type", "text/plain")
        except:
            pass
        self._serialize_response(resp^, False)

    def _serialize_static(
        mut self, resp: StaticResponse, keep_alive: Bool
    ) -> None:
        """Queue a pre-encoded static response into ``write_buf``.

        Reuses the buffer's existing capacity across requests (same
        pattern as ``_serialize_response``) and pulls either the
        keep-alive or close variant of the pre-encoded bytes depending
        on ``keep_alive``.
        """
        self.write_buf.clear()
        self.write_pos = 0
        # Pick the keep-alive or close variant by branch rather than via
        # a conditional expression. ``List[UInt8]`` is no longer
        # ``ImplicitlyCopyable`` under Mojo 1.0.0b1+, so binding the
        # selected variant to a single ``var`` would force an implicit
        # copy that the compiler now rejects. Splitting the branch
        # keeps both arms in pure borrow + ``unsafe_ptr()`` form and
        # avoids any copy at all.
        var n: Int
        if keep_alive:
            n = len(resp.keepalive_bytes)
        else:
            n = len(resp.close_bytes)
        if self.write_buf.capacity < n:
            self.write_buf.reserve(n)
        self.write_buf.resize(n, UInt8(0))
        if keep_alive:
            memcpy(
                dest=self.write_buf.unsafe_ptr(),
                src=resp.keepalive_bytes.unsafe_ptr(),
                count=n,
            )
        else:
            memcpy(
                dest=self.write_buf.unsafe_ptr(),
                src=resp.close_bytes.unsafe_ptr(),
                count=n,
            )
        self.write_pos = 0

    def _serialize_response(mut self, resp: Response, keep_alive: Bool) -> None:
        """Serialise ``resp`` into ``write_buf`` ready to be sent."""
        var reason = resp.reason
        if reason.byte_length() == 0:
            reason = _status_reason(resp.status)
        var body_len = len(resp.body)

        var estimated = 64 + body_len
        for i in range(resp.headers.len()):
            estimated += (
                resp.headers._keys[i].byte_length()
                + resp.headers._values[i].byte_length()
                + 4
            )
        # Reuse self.write_buf's allocated capacity across requests —
        # on_writable already clears the buffer on flush, so its backing
        # storage is idle. Avoids a per-request List allocation.
        self.write_buf.clear()
        self.write_pos = 0
        if self.write_buf.capacity < estimated:
            self.write_buf.reserve(estimated)
        var wire = self.write_buf^

        _append_str(wire, "HTTP/1.1 ")
        _append_int(wire, resp.status)
        _append_str(wire, " ")
        _append_str(wire, reason)
        _append_str(wire, "\r\n")

        for i in range(resp.headers.len()):
            var k = resp.headers._keys[i]
            # Case-insensitive skip of Content-Length, Connection,
            # and Date without allocating a lowercased copy each
            # header. Compare only the length-matching candidates.
            # Date is always emitted by us from the per-connection
            # DateCache; any caller-supplied Date is dropped (RFC
            # 9110 §6.6.1: single Date field-line per response).
            if _is_content_length(k) or _is_connection(k) or _is_date(k):
                continue
            _append_str(wire, k)
            _append_str(wire, ": ")
            _append_str(wire, resp.headers._values[i])
            _append_str(wire, "\r\n")

        _append_str(wire, "Content-Length: ")
        _append_int(wire, body_len)
        _append_str(wire, "\r\n")

        # Date: RFC 9110 §6.6.1, IMF-fixdate from the per-connection
        # DateCache. The cache calls clock_gettime + (re)formats only
        # when the wall-clock second has advanced; reads on the same
        # second return the cached 29-byte buffer directly.
        self._date_cache.refresh()
        var date_bytes = self._date_cache.current_bytes()
        _append_str(wire, "Date: ")
        var date_old_len = len(wire)
        wire.resize(date_old_len + len(date_bytes), UInt8(0))
        memcpy(
            dest=wire.unsafe_ptr() + date_old_len,
            src=date_bytes.unsafe_ptr(),
            count=len(date_bytes),
        )
        _append_str(wire, "\r\n")

        if keep_alive:
            _append_str(wire, "Connection: keep-alive\r\n")
        else:
            _append_str(wire, "Connection: close\r\n")

        _append_str(wire, "\r\n")

        # Bulk-copy the body. Appending byte-by-byte from ``resp.body``
        # dominated this function's cost on small-body responses.
        if body_len > 0:
            var old = len(wire)
            wire.resize(old + body_len, UInt8(0))
            memcpy(
                dest=wire.unsafe_ptr() + old,
                src=resp.body.unsafe_ptr(),
                count=body_len,
            )

        self.write_buf = wire^
        self.write_pos = 0
