"""``flare.h3.server`` -- HTTP/3 server connection driver.

Wraps the sans-I/O HTTP/3 codec primitives
(:class:`flare.h3.H3RequestReader`,
:func:`flare.h3.encode_response_headers`) and the QUIC connection
driver (:class:`flare.quic.server.QuicConnection`) into a per-
connection HTTP/3 server.

## Stream layout (RFC 9114 §6)

HTTP/3 over QUIC uses four families of streams:

* **Bidirectional request streams** -- one per request/response
  exchange. The client opens, sends HEADERS + DATA frames; the
  server replies on the same stream with HEADERS + DATA + (FIN).
* **Unidirectional control stream** (type 0x00) -- exactly one
  per direction; carries SETTINGS first, then GOAWAY /
  MAX_PUSH_ID over the connection lifetime.
* **Unidirectional push stream** (type 0x01) -- server-initiated.
  Not implemented in the v0.8 cycle (RFC 9114 deprecates push as
  of revision 9).
* **Unidirectional QPACK encoder stream** (type 0x02) +
  **decoder stream** (type 0x03) -- carry dynamic-table
  instructions. The v0.8 scaffold runs QPACK in static-table-only
  mode (dynamic-table inserts ship in the Track Q4 follow-up).

## What ships here

- :class:`H3ConnectionConfig` -- per-connection HTTP/3 config:
  max field section size, max blocked streams, the GOAWAY
  threshold above which the server stops accepting new
  request streams.
- :class:`H3Connection` -- the per-connection driver carrier.
  Owns the per-stream :class:`H3RequestReader` instances (keyed
  by QUIC stream ID), the per-stream accumulated request state,
  and the per-stream pending outbound bytes.
- :class:`H3StreamType` -- the unidirectional-stream type
  codepoints from RFC 9114 §6.2.

The driver is sans-I/O: the QUIC reactor feeds reassembled stream
chunks in via :meth:`H3Connection.feed_stream_chunk` and drains
pending outbound frames via :meth:`H3Connection.take_response_frames`.
The Handler dispatch sits on the QUIC reactor side (Track Q5);
the H3 layer surfaces the Request once it's fully reassembled and
the reactor calls :meth:`H3Connection.emit_response` once the
Handler returns.

References:
- RFC 9114 "HTTP/3".
- RFC 9204 "QPACK: Field Compression for HTTP/3".
"""

from std.collections import Dict, List, Optional
from std.memory import Span

from flare.h3.request_reader import (
    H3_REQUEST_STATE_DONE,
    H3RequestEventHandler,
    H3RequestReader,
    feed_into,
)
from flare.h3.response_writer import (
    encode_response_data,
    encode_response_headers,
    encode_response_trailers,
)
from flare.http.request import Request
from flare.http.response import Response
from flare.qpack import QpackHeader


# ── Unidirectional stream type codepoints (RFC 9114 §6.2) ───────────────


struct H3StreamType:
    """RFC 9114 §6.2 unidirectional stream types.

    Each uni stream's first varint is the stream type; the reader
    dispatches on this varint to the matching internal state
    machine (control / push / qpack-enc / qpack-dec).
    """

    comptime CONTROL: Int = 0x00
    """RFC 9114 §6.2.1 -- control stream. Carries SETTINGS,
    GOAWAY, MAX_PUSH_ID. Exactly one per direction."""

    comptime PUSH: Int = 0x01
    """RFC 9114 §6.2.2 -- push stream. Server-initiated.
    Deprecated as of RFC 9114 revision 9; this codepoint is
    carried so the reader can reject incoming push streams with
    H3_STREAM_CREATION_ERROR."""

    comptime QPACK_ENCODER: Int = 0x02
    """RFC 9204 §4.2 -- QPACK encoder stream. Carries dynamic-
    table insert instructions."""

    comptime QPACK_DECODER: Int = 0x03
    """RFC 9204 §4.2 -- QPACK decoder stream. Carries
    section-acknowledgement + stream-cancellation instructions."""


# ── Configuration carrier ──────────────────────────────────────────────


struct H3ConnectionConfig(Copyable, Defaultable, Movable):
    """Per-connection HTTP/3 settings.

    The server advertises these via the control stream's SETTINGS
    frame (RFC 9114 §7.2.4). Production defaults match the values
    the OpenAPI gen + the cookbook examples expect.
    """

    var max_field_section_size: UInt64
    """RFC 9114 §7.2.4.2 -- maximum total size (in bytes) the
    server will accept for a single field section. Default:
    65536. The reader rejects oversize header blocks with
    H3_EXCESSIVE_LOAD."""

    var qpack_max_table_capacity: UInt64
    """RFC 9204 §3.2.2 -- maximum bytes the server is willing to
    spend on the QPACK dynamic table. Default 0 means static-
    table-only mode (the Track Q4 scaffold default)."""

    var qpack_blocked_streams: UInt64
    """RFC 9204 §3.2.3 -- maximum streams the server is willing
    to leave blocked on QPACK dynamic-table insertions. Default
    0 (paired with qpack_max_table_capacity=0)."""

    var enable_connect_protocol: Bool
    """RFC 9220 §3 -- whether to advertise CONNECT-Protocol
    support for WebSocket / WebTransport bootstrapping. Default
    True since the rest of flare supports CONNECT semantics."""

    var goaway_threshold_streams: UInt64
    """Local soft cap on the stream count above which the server
    emits GOAWAY and refuses new request streams. Default
    UINT64_MAX (effectively no cap; mirrors the H2 server's
    behaviour)."""

    def __init__(out self):
        self.max_field_section_size = UInt64(65536)
        self.qpack_max_table_capacity = UInt64(0)
        self.qpack_blocked_streams = UInt64(0)
        self.enable_connect_protocol = True
        self.goaway_threshold_streams = UInt64((1 << 63) - 1)


# ── Per-stream accumulator + event collector ──────────────────────────


struct _H3StreamState(Copyable, Defaultable, Movable):
    """Per-bidirectional-stream H3 server state.

    Carries everything that accumulates over the lifetime of a
    request stream: the reader's frame-by-frame state machine,
    the reassembled request bytes/headers, the pending outbound
    response bytes, and the protocol-level flags the reactor
    consults to decide when a stream is ready for handler
    dispatch + when it's safe to retire.
    """

    var reader: H3RequestReader
    """Sans-I/O frame reader. ``feed_stream_chunk`` advances this
    one frame at a time."""

    var inbox: List[UInt8]
    """Inbound bytes accumulated across stream-chunk arrivals.
    The frame reader can require multiple chunks before a single
    frame is complete (NEEDS_MORE)."""

    var headers: List[QpackHeader]
    """Decoded request HEADERS. Populated by the first
    ``on_headers`` callback."""

    var body: List[UInt8]
    """Reassembled request body across one or more ``on_data``
    callbacks."""

    var trailers: List[QpackHeader]
    """Decoded trailing HEADERS (empty if the client didn't send
    trailers)."""

    var headers_complete: Bool
    """Set after the first ``on_headers`` callback fires. The
    reactor uses this to decide when a stream is ready for
    handler dispatch even when the body is still streaming."""

    var fin_received: Bool
    """Set when the QUIC stream signals end-of-stream (the FIN
    bit on the last STREAM frame). The reactor calls
    :meth:`H3Connection.signal_end_of_stream` to flip this; the
    sans-I/O reader has no FIN signal of its own."""

    var protocol_error: String
    """Empty when the reader hasn't hit a protocol error; the
    error message on ``on_protocol_error``. The reactor maps
    this to an H3_FRAME_UNEXPECTED / QPACK_DECOMPRESSION_FAILED
    stream-level error to the QUIC peer."""

    var unknown_frames: List[UInt64]
    """List of unknown frame-type identifiers the reader saw
    (RFC 9114 §7.2.8 says receivers MUST ignore unknown frames;
    we keep the list so the reactor can optionally log them)."""

    var outbox: List[UInt8]
    """Pending outbound response bytes produced by
    :meth:`H3Connection.emit_response`. Drained by
    :meth:`H3Connection.take_response_frames`."""

    var response_emitted: Bool
    """Set when ``emit_response`` has been called for this
    stream. The reactor flips this False between requests if
    pipelining over the same QUIC stream is enabled (RFC 9114
    forbids HTTP/3 pipelining on a single bidi stream, so this
    stays True until the stream closes)."""

    var request_taken: Bool
    """Set when the reactor has called :meth:`take_request`.
    Guards against the reactor double-dispatching the same
    request through a Handler."""

    def __init__(out self):
        self.reader = H3RequestReader.new()
        self.inbox = List[UInt8]()
        self.headers = List[QpackHeader]()
        self.body = List[UInt8]()
        self.trailers = List[QpackHeader]()
        self.headers_complete = False
        self.fin_received = False
        self.protocol_error = String("")
        self.unknown_frames = List[UInt64]()
        self.outbox = List[UInt8]()
        self.response_emitted = False
        self.request_taken = False

    @staticmethod
    def with_limits(max_field_section_bytes: UInt64) -> Self:
        var out = Self()
        out.reader = H3RequestReader.new(max_field_section_bytes)
        return out^


@fieldwise_init
struct _H3EventCollector(H3RequestEventHandler, Movable):
    """Internal handler the H3 server passes to ``feed_into``.

    Records callback invocations into typed buffers; the
    surrounding :meth:`H3Connection.feed_stream_chunk` drains
    these into the per-stream :class:`_H3StreamState` after the
    frame-reader returns. Splitting the recorder from the
    state-update step keeps the event-handler trait surface
    small (no driver-context plumbing through callbacks)."""

    var headers: List[QpackHeader]
    """Buffered headers from the most-recent ``on_headers``
    callback. Empty unless the reader fired ``on_headers``
    during the current ``feed_into`` invocation."""

    var headers_fired: Bool
    """True iff the current ``feed_into`` fired ``on_headers``."""

    var data: List[UInt8]
    """Buffered body bytes from the most-recent ``on_data``
    callback. Empty unless the reader fired ``on_data``."""

    var data_fired: Bool
    """True iff the current ``feed_into`` fired ``on_data``."""

    var trailers: List[QpackHeader]
    """Buffered trailers from the most-recent ``on_trailers``
    callback."""

    var trailers_fired: Bool
    """True iff the current ``feed_into`` fired ``on_trailers``."""

    var unknown_frame_type: UInt64
    """Most-recent unknown-frame type id from
    ``on_unknown_frame``."""

    var unknown_fired: Bool
    """True iff the current ``feed_into`` fired
    ``on_unknown_frame``."""

    var error_message: String
    """Protocol-error message from ``on_protocol_error``."""

    var error_fired: Bool
    """True iff the current ``feed_into`` fired
    ``on_protocol_error``."""

    @staticmethod
    def new() -> Self:
        return Self(
            headers=List[QpackHeader](),
            headers_fired=False,
            data=List[UInt8](),
            data_fired=False,
            trailers=List[QpackHeader](),
            trailers_fired=False,
            unknown_frame_type=UInt64(0),
            unknown_fired=False,
            error_message=String(""),
            error_fired=False,
        )

    def on_headers(mut self, headers: List[QpackHeader]) raises:
        self.headers = headers.copy()
        self.headers_fired = True

    def on_data(mut self, data: List[UInt8]) raises:
        self.data = data.copy()
        self.data_fired = True

    def on_trailers(mut self, trailers: List[QpackHeader]) raises:
        self.trailers = trailers.copy()
        self.trailers_fired = True

    def on_unknown_frame(mut self, type_id: UInt64) raises:
        self.unknown_frame_type = type_id
        self.unknown_fired = True

    def on_protocol_error(mut self, message: String) raises:
        self.error_message = message
        self.error_fired = True


# ── Per-connection driver ──────────────────────────────────────────────


struct H3Connection(Defaultable, Movable):
    """Per-connection HTTP/3 server driver.

    Owned by the QUIC reactor. One instance per QUIC connection
    that negotiated the ``h3`` ALPN identifier. The driver:

    * Tracks per-bidirectional-stream :class:`_H3StreamState`
      instances keyed by QUIC stream ID. Each carrier owns the
      sans-I/O frame reader, the accumulated request bytes /
      headers / body / trailers, and the pending outbound
      response bytes.
    * Carries the SETTINGS the server announced + the client
      announced.
    * Tracks the control-stream lifecycle (whether the peer's
      SETTINGS arrived yet, whether GOAWAY was emitted).
    * Carries the QPACK state. Static-table-only in v0.8;
      dynamic-table inserts ship with the Track Q4 follow-up.

    The driver is sans-I/O: the QUIC reactor feeds reassembled
    stream chunks in via :meth:`feed_stream_chunk` and drains
    pending outbound frames via :meth:`take_response_frames`.
    The Handler dispatch happens on the reactor side -- the H3
    layer surfaces the assembled :class:`Request` via
    :meth:`take_request` and accepts the matching
    :class:`Response` via :meth:`emit_response`.
    """

    var config: H3ConnectionConfig
    """Local configuration -- the values the server advertises
    via SETTINGS."""

    var peer_settings_received: Bool
    """Whether the peer's SETTINGS frame has arrived on the
    control stream yet. Until True, the driver buffers any
    application traffic that would depend on the negotiated
    field-section-size + QPACK parameters."""

    var goaway_emitted: Bool
    """Whether the server has emitted GOAWAY. Once True, new
    request streams are rejected with H3_REQUEST_CANCELLED."""

    var streams: Dict[Int, _H3StreamState]
    """Per-stream state carriers. Keys are QUIC stream IDs.
    Streams are removed via :meth:`close_request_stream` once
    the response is fully drained from the outbox."""

    var control_stream_id: Int
    """QUIC stream ID of the locally-opened control stream. -1
    until the driver opens the control stream during connection
    setup."""

    var qpack_encoder_stream_id: Int
    """QUIC stream ID of the locally-opened QPACK encoder
    stream. -1 in static-only mode."""

    var qpack_decoder_stream_id: Int
    """QUIC stream ID of the locally-opened QPACK decoder
    stream. -1 in static-only mode."""

    def __init__(out self):
        self.config = H3ConnectionConfig()
        self.peer_settings_received = False
        self.goaway_emitted = False
        self.streams = Dict[Int, _H3StreamState]()
        self.control_stream_id = -1
        self.qpack_encoder_stream_id = -1
        self.qpack_decoder_stream_id = -1

    @staticmethod
    def with_config(config: H3ConnectionConfig) -> Self:
        """Construct with a non-default config carrier."""
        var out = Self()
        out.config = config.copy()
        return out^

    def open_request_stream(mut self, stream_id: Int) raises:
        """Allocate a per-stream carrier for an inbound
        bidirectional QUIC stream. Idempotent: re-opening the
        same stream ID is a no-op (the QUIC reactor occasionally
        fires the open event redundantly when a stream sees
        both HEADERS and DATA before the dispatcher polls).
        """
        if stream_id in self.streams:
            return
        if self.goaway_emitted:
            raise Error(
                "H3Connection.open_request_stream: GOAWAY emitted;"
                " new request streams are rejected"
            )
        self.streams[stream_id] = _H3StreamState.with_limits(
            self.config.max_field_section_size
        )

    def close_request_stream(mut self, stream_id: Int) raises:
        """Drop the per-stream carrier. Called after the
        response FIN has been emitted (so the server doesn't
        keep parser state around for a stream that's done)."""
        if stream_id in self.streams:
            _ = self.streams.pop(stream_id)

    def has_stream(self, stream_id: Int) -> Bool:
        """Whether the driver currently tracks a carrier for
        this stream ID. Useful for testing the open / close
        lifecycle without needing the full reactor."""
        return stream_id in self.streams

    def active_request_count(self) -> Int:
        """Number of active per-stream carriers. The reactor
        uses this to decide when to emit GOAWAY (above
        ``goaway_threshold_streams``)."""
        return len(self.streams)

    def stream_has_headers(self, stream_id: Int) raises -> Bool:
        """Whether the first HEADERS frame has been fully parsed
        on ``stream_id``. The reactor checks this to decide when
        a stream is ready for handler dispatch (HEADERS alone is
        enough for a GET; DATA + FIN is required for methods
        with a body)."""
        if stream_id not in self.streams:
            return False
        return self.streams[stream_id].headers_complete

    def stream_fin_received(self, stream_id: Int) raises -> Bool:
        """Whether the QUIC layer has signalled FIN on
        ``stream_id``. Set via :meth:`signal_end_of_stream`."""
        if stream_id not in self.streams:
            return False
        return self.streams[stream_id].fin_received

    def stream_protocol_error(self, stream_id: Int) raises -> String:
        """Per-stream protocol-error message; empty when the
        reader has not hit a protocol error."""
        if stream_id not in self.streams:
            return String("")
        return String(self.streams[stream_id].protocol_error)

    def feed_stream_chunk(
        mut self, stream_id: Int, var chunk: List[UInt8]
    ) raises:
        """Feed a reassembled stream-data chunk into the per-
        stream reader.

        Idempotently allocates the stream's carrier if it isn't
        tracked yet (a chunk arriving for an unseen bidi stream
        is the open-stream signal). Appends the chunk to the
        per-stream inbox, then drains the inbox one frame at a
        time via :func:`feed_into`. Each frame's callback fires
        through a transient :class:`_H3EventCollector`; the
        collector's contents are merged into the per-stream
        accumulator after the call returns.

        Returns when either:

        * ``feed_into`` returns NEEDS_MORE (the inbox doesn't
          yet hold a complete next frame).
        * The reader transitions to ``DONE`` (trailers fired,
          protocol error, or stream-level shutdown).
        """
        if stream_id not in self.streams:
            self.open_request_stream(stream_id)
        var state = self.streams[stream_id].copy()
        for i in range(len(chunk)):
            state.inbox.append(chunk[i])
        var cursor = 0
        while cursor < len(state.inbox):
            var collector = _H3EventCollector.new()
            var view = state.inbox[cursor:]
            var consumed = feed_into(
                state.reader, Span[UInt8, _](view), collector
            )
            if consumed == 0:
                break
            cursor += consumed
            if collector.headers_fired:
                if state.headers_complete:
                    # A second HEADERS frame is the trailers
                    # frame; the reader fires on_trailers for
                    # that path. Anything else means we somehow
                    # got two on_headers callbacks; treat as a
                    # protocol error so the reactor can clean
                    # the stream up.
                    state.protocol_error = String(
                        "h3 server: unexpected duplicate HEADERS"
                    )
                else:
                    state.headers = collector.headers.copy()
                    state.headers_complete = True
            if collector.data_fired:
                for j in range(len(collector.data)):
                    state.body.append(collector.data[j])
            if collector.trailers_fired:
                state.trailers = collector.trailers.copy()
            if collector.unknown_fired:
                state.unknown_frames.append(collector.unknown_frame_type)
            if collector.error_fired:
                state.protocol_error = String(collector.error_message)
                break
            if state.reader.state == H3_REQUEST_STATE_DONE:
                break
        # Drop the consumed prefix from the inbox so the next
        # chunk doesn't re-parse old bytes.
        if cursor > 0:
            var rest = List[UInt8](capacity=len(state.inbox) - cursor)
            for k in range(cursor, len(state.inbox)):
                rest.append(state.inbox[k])
            state.inbox = rest^
        self.streams[stream_id] = state^

    def signal_end_of_stream(mut self, stream_id: Int) raises:
        """Signal that the QUIC layer observed FIN on
        ``stream_id``. The reader's sans-I/O frame state has
        no FIN signal of its own, so the reactor must inform
        the H3 driver via this method when the last STREAM
        frame on the request side carries the FIN bit. Used by
        the reactor to decide when a request-with-body has
        been fully reassembled."""
        if stream_id not in self.streams:
            return
        var state = self.streams[stream_id].copy()
        state.fin_received = True
        self.streams[stream_id] = state^

    def take_completed_streams(self) raises -> List[Int]:
        """Return the IDs of streams that have a request ready
        for handler dispatch.

        A stream is ready when:

        * The first HEADERS frame has been fully parsed
          (``headers_complete=True``), AND
        * Either the request has no body (FIN observed) or the
          reader has reached DONE (trailers fired), AND
        * The reactor has not already pulled this request via
          :meth:`take_request`, AND
        * No protocol error has fired on the stream.
        """
        var ready = List[Int]()
        for entry in self.streams.items():
            var state = entry.value.copy()
            if state.request_taken:
                continue
            if not state.headers_complete:
                continue
            if state.protocol_error.byte_length() != 0:
                continue
            var done = state.fin_received or (
                state.reader.state == H3_REQUEST_STATE_DONE
            )
            if not done:
                continue
            ready.append(entry.key)
        return ready^

    def take_request(mut self, stream_id: Int) raises -> Request:
        """Assemble + return the :class:`Request` for
        ``stream_id``. Idempotent guard: subsequent calls on the
        same stream raise so the reactor can't accidentally
        dispatch the same request through a Handler twice."""
        if stream_id not in self.streams:
            raise Error(
                "H3Connection.take_request: stream not tracked: "
                + String(stream_id)
            )
        var state = self.streams[stream_id].copy()
        if state.request_taken:
            raise Error(
                "H3Connection.take_request: request already taken on stream "
                + String(stream_id)
            )
        if not state.headers_complete:
            raise Error(
                "H3Connection.take_request: HEADERS frame not yet parsed on"
                " stream "
                + String(stream_id)
            )
        var method = String("GET")
        var path = String("/")
        for i in range(len(state.headers)):
            var name = state.headers[i].name
            var value = state.headers[i].value
            if name == ":method":
                method = String(value)
            elif name == ":path":
                path = String(value)
        var req = Request(method=method^, url=path^, body=state.body.copy())
        for i in range(len(state.headers)):
            var name = state.headers[i].name
            if (
                name == ":method"
                or name == ":path"
                or name == ":scheme"
                or name == ":authority"
            ):
                continue
            req.headers.set(state.headers[i].name, state.headers[i].value)
        state.request_taken = True
        self.streams[stream_id] = state^
        return req^

    def emit_response(mut self, stream_id: Int, var response: Response) raises:
        """Encode ``response`` into the per-stream outbox so the
        reactor can drain it via :meth:`take_response_frames`.

        Emits HEADERS + (zero or more) DATA frames. Trailers
        and the FIN bit are handled by the reactor (FIN is a
        QUIC-level signal); this method only buffers the H3
        frame bytes. Idempotent guard: emitting twice for the
        same stream raises so the reactor can't accidentally
        write a stale response after the stream is finalized.
        """
        if stream_id not in self.streams:
            raise Error(
                "H3Connection.emit_response: stream not tracked: "
                + String(stream_id)
            )
        var state = self.streams[stream_id].copy()
        if state.response_emitted:
            raise Error(
                "H3Connection.emit_response: response already emitted on"
                " stream "
                + String(stream_id)
            )
        var headers = List[QpackHeader]()
        for i in range(response.headers.len()):
            var name = response.headers._keys[i]
            var value = response.headers._values[i]
            headers.append(QpackHeader(String(name), String(value)))
        encode_response_headers(response.status, headers, state.outbox)
        if len(response.body) != 0:
            encode_response_data(Span[UInt8, _](response.body), state.outbox)
        state.response_emitted = True
        self.streams[stream_id] = state^

    def take_response_frames(mut self, stream_id: Int) raises -> List[UInt8]:
        """Drain pending outbound bytes for ``stream_id`` and
        return them to the reactor for emission as QUIC stream-
        data. Returns an empty list when nothing is queued. The
        reactor calls this repeatedly until it returns empty;
        each call is destructive (drained bytes are not held
        for re-reads)."""
        if stream_id not in self.streams:
            raise Error(
                "H3Connection.take_response_frames: stream not tracked: "
                + String(stream_id)
            )
        var state = self.streams[stream_id].copy()
        var drained = state.outbox^
        state.outbox = List[UInt8]()
        self.streams[stream_id] = state^
        return drained^
