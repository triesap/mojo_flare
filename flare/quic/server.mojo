"""``flare.quic.server`` -- QUIC server reactor.

Wraps the sans-I/O QUIC connection state machine
(:class:`flare.quic.state.Connection`) in a UDP listener +
per-connection dispatcher. The per-datagram dispatch loop
threads bytes through :class:`OpenSslQuicCrypto` packet
protection, the transport-frame parser, and
:meth:`Connection.handle_frame` to produce
:class:`ConnectionEvents` for the H3 driver above; PTO /
idle / ack-delay timers sit on the shared TimerWheel; CC +
pacing budget gate ``sendmmsg`` on the egress path.

## What ships here

- :class:`QuicServerConfig` -- bind configuration: host, port,
  rustls config carrier, congestion-controller choice, idle
  timeout, max packet size.
- :class:`QuicListener` -- factory that owns a bound UDP
  socket plus the per-connection dispatch table. The :meth:`bind`
  factory opens the socket, :meth:`tick` drains one datagram
  (unit-testable), :meth:`run` is the blocking event loop, and
  :meth:`shutdown` requests a clean exit.
- :class:`QuicConnection` -- per-connection driver that
  composes the existing :class:`flare.quic.state.Connection`
  state machine with a :trait:`flare.quic.cc.CongestionController`
  carrier and the rustls QUIC session.
- :class:`ConnectionIdTable` -- per-listener routing table from
  Connection ID to connection slot, used by the dispatch loop
  to route inbound datagrams via the Destination Connection ID
  in the packet header (RFC 9000 §5.1).

References:
- RFC 9000 §5 "Connections" -- Connection ID routing.
- RFC 9000 §10 "Connection Termination" -- idle / draining.
- RFC 9000 §17 "Packet Formats" -- long / short header parse
  for the dispatch path.
- RFC 9002 §6.2 "PTO and probe packets" -- PTO timer wiring.
"""

from std.collections import Dict, List, Optional
from std.ffi import c_int, external_call
from std.memory import Span, stack_allocation

from ..net.address import IpAddr, SocketAddr
from ..udp import UdpSocket
from .cc import (
    CcChoice,
    CcState,
    cc_init,
    on_ack_received,
    on_packet_sent,
    on_packets_lost,
    pacing_budget,
)
from .crypto import QuicAead
from .frame import CryptoFrame, StreamFrame, encode_crypto
from .packet import (
    ConnectionId,
    LongHeader,
    MAX_CID_LENGTH,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    PACKET_TYPE_HANDSHAKE,
    encode_long_header,
    parse_long_header,
    parse_short_header,
)
from .protection import (
    decode_packet_number,
    protect_initial_packet,
    unprotect_1rtt_packet,
    unprotect_handshake_packet,
    unprotect_initial_packet,
)
from .varint import encode_varint
from .state import (
    Connection,
    ConnectionEvents,
    CONN_STATE_CLOSED,
    CONN_STATE_DRAINING,
    empty_events,
    handle_frame_buf,
    new_connection,
)
from ..h3.server import H3Connection
from ..http.request import Request
from ..http.response import Response
from .timers import (
    TIMER_KIND_ACK_DELAY,
    TIMER_KIND_IDLE,
    TIMER_KIND_PTO,
    decode_timer_token,
    encode_timer_token,
)
from ..runtime.timer_wheel import TimerWheel
from ..tls.rustls_quic import (
    QuicEncryptionLevel,
    RustlsQuicAcceptor,
    RustlsQuicConfig,
)
from ..tls._rustls_quic_ffi import (
    _do_accept,
    _do_feed_crypto,
    _do_have_keys,
    _do_header_decrypt,
    _do_header_encrypt,
    _do_is_handshake_complete,
    _do_packet_decrypt,
    _do_packet_encrypt,
    _do_session_free,
    _do_take_crypto,
)
from .packet import encode_short_header


def _inbound_level_for_datagram(datagram: Span[UInt8, _]) -> Int:
    """Derive the QUIC encryption level of an inbound datagram
    from its first byte.

    The MSB of the first byte is the header-form bit: 1 == long
    header, 0 == short header.  Long-header type bits 4-5 encode
    the packet type per RFC 9000 §17.2 (0=Initial, 1=0-RTT,
    2=Handshake, 3=Retry).  Short-header packets are always 1-RTT
    (RFC 9000 §17.3).

    Returns the matching :data:`QuicEncryptionLevel` codepoint.
    Empty datagrams and Retry packets fall back to INITIAL --
    Retry doesn't carry CRYPTO so the level choice is moot for
    the rustls dispatch (Retry decode is a separate path that
    never reaches `_dispatch_crypto_frames`).
    """
    if len(datagram) < 1:
        return QuicEncryptionLevel.INITIAL
    var first = Int(datagram[0])
    var is_long = (first & 0x80) != 0
    if not is_long:
        return QuicEncryptionLevel.APPLICATION
    var pt = (first & 0x30) >> 4
    if pt == 0:
        return QuicEncryptionLevel.INITIAL
    if pt == 1:
        return QuicEncryptionLevel.EARLY_DATA
    if pt == 2:
        return QuicEncryptionLevel.HANDSHAKE
    return QuicEncryptionLevel.INITIAL  # Retry -- moot for CRYPTO dispatch


def _ready_sentinel() -> List[UInt8]:
    """Single-byte readiness marker stamped onto
    :attr:`QuicConnection.rx_handshake_secret` /
    `.tx_handshake_secret` / `.rx_1rtt_secret` / `.tx_1rtt_secret`
    when rustls installs per-level `Keys`.

    rustls keeps `quic::Secrets` sealed (`pub(crate)`) and only
    hands back trait-object key handles, so post-Initial AEAD
    routes through `RustlsQuicSession.packet_{encrypt,decrypt}` +
    `.header_{encrypt,decrypt}`. The Mojo side never sees raw
    traffic secrets; the sentinel just flips the
    `len(rx_*_secret) == 0` readiness gates.
    """
    var out = List[UInt8]()
    out.append(UInt8(0xFF))
    return out^


# -- Monotonic clock helper --------------------------------------------


def _monotonic_ms() -> UInt64:
    """Return the monotonic clock in milliseconds.

    Uses ``clock_gettime(CLOCK_MONOTONIC, ...)``. The constant value
    1 for ``CLOCK_MONOTONIC`` is portable between Linux and macOS
    (macOS has supported it since 10.12). Same shape as
    :func:`flare.http._reactor.keepalive_scan._monotonic_ms` but
    returns ``UInt64`` so it composes with :class:`TimerWheel`
    without an extra cast.
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
    return UInt64(Int(sec) * 1000 + Int(nsec) // 1_000_000)


# -- Per-slot rustls QUIC session carrier ------------------------------


@fieldwise_init
struct _SessionSlot(Copyable, Movable):
    """Per-slot rustls QUIC session state.

    Non-owning carrier: the per-listener slab
    (:attr:`QuicListener.tls_sessions`) is the sole owner of the
    Rust-side ``Box<Session>``. Every per-connection bridge call
    routes the FFI through the listener's pinned
    ``tls_acceptor._lib`` borrow so :class:`OwnedDLHandle`'s
    refcount keeps ``libflare_rustls_quic.so`` mapped across the
    call. The slab's element type is ``_SessionSlot`` rather than
    :class:`flare.tls.rustls_quic.RustlsQuicSession` because the
    latter is ``Movable``-only and ``List[T]`` requires
    ``T: Copyable``. Carrier copy is safe: the integer ``handle``
    is a non-owning view, and the slab's :meth:`QuicListener.__del__`
    is the unique site that calls
    :func:`flare.tls._rustls_quic_ffi._do_session_free` -- never
    a slot's destructor.
    """

    var handle: Int
    """Raw ``Box<Session>*`` (as ``Int``); 0 = NULL sentinel
    (empty-PEM config or acceptor-rejected accept). The dispatcher
    treats 0 as the silent-drop path per RFC 9001 §5.2."""

    var level: Int
    """Current outbound encryption level (one of the
    :class:`flare.tls.rustls_quic.QuicEncryptionLevel` codepoints).
    Starts at ``INITIAL``; advances as the rustls KeyChange enum
    surfaces handshake + 1-RTT keys."""


# -- Configuration carrier ----------------------------------------------


struct QuicServerConfig(Copyable, Defaultable, Movable):
    """Bind-time configuration for the QUIC server reactor.

    Most fields have sensible production defaults; the user
    supplies a :class:`RustlsQuicConfig` (certificate + key + ALPN
    list) and optionally overrides the timeouts + CC choice.
    """

    var host: String
    """IPv4/IPv6 address to bind the UDP listener to. Default is
    ``"0.0.0.0"`` for IPv4 wildcard binding."""

    var port: UInt16
    """UDP port. Default 0 means "let the kernel pick" -- caller
    reads the resolved port back via
    :meth:`QuicListener.local_addr` after :meth:`QuicListener.bind`."""

    var rustls_config: RustlsQuicConfig
    """The rustls QUIC server configuration carrier. Provides the
    certificate chain, private key, ALPN list, and 0-RTT toggle."""

    var cc_choice: Int
    """Congestion controller selector
    (:data:`flare.quic.cc.CcChoice.CUBIC` for production,
    :data:`flare.quic.cc.CcChoice.RENO` for deterministic tests).
    Default: CUBIC."""

    var aead_choice: Int
    """AEAD selector codepoint (:class:`flare.quic.crypto.QuicAead`).
    Default: AES-128-GCM (the QUIC v1 mandatory-to-implement)."""

    var max_idle_timeout_ms: UInt64
    """RFC 9000 §10.1 max-idle-timeout in milliseconds. The server
    advertises this to clients; connections idle for longer get
    silently dropped. Default: 30_000 ms (30 s)."""

    var max_udp_payload_size: UInt64
    """RFC 9000 §18.2 max-udp-payload-size transport parameter --
    the largest UDP datagram payload the server is willing to
    receive. Default: 1452 bytes (Ethernet MTU 1500 minus IPv6 40
    byte header minus 8 byte UDP header)."""

    var initial_max_data: UInt64
    """RFC 9000 §4 connection-level flow-control limit -- total
    bytes the server is willing to receive across all streams
    before MAX_DATA is required. Default: 1 MiB."""

    var initial_max_streams_bidi: UInt64
    """RFC 9000 §4.6 client-initiated bidi streams limit. Default:
    100 -- matches the H3 server's working set (control + qpack-
    enc + qpack-dec + N request streams)."""

    var initial_max_streams_uni: UInt64
    """RFC 9000 §4.6 client-initiated uni streams limit. Default:
    3 -- H3 needs control + qpack-encoder + qpack-decoder."""

    var local_cid_length: Int
    """Length in bytes of the Connection IDs this server issues
    to peers. RFC 9000 §5.1 caps at 20; 8 is the aioquic /
    quinn / quiche default and is what the dispatch loop assumes
    when parsing short-header packets after the handshake."""

    def __init__(out self):
        self.host = String("0.0.0.0")
        self.port = UInt16(0)
        self.rustls_config = RustlsQuicConfig()
        self.cc_choice = CcChoice.CUBIC
        self.aead_choice = QuicAead.AES_128_GCM
        self.max_idle_timeout_ms = UInt64(30_000)
        self.max_udp_payload_size = UInt64(1452)
        self.initial_max_data = UInt64(1 << 20)  # 1 MiB
        self.initial_max_streams_bidi = UInt64(100)
        self.initial_max_streams_uni = UInt64(3)
        self.local_cid_length = 8


# -- Per-connection driver ----------------------------------------------


struct QuicConnection(Copyable, Movable):
    """Per-connection driver wrapping :class:`flare.quic.state.Connection`.

    Owned by the reactor; one instance per active connection.
    Composes:

    - The sans-I/O :class:`flare.quic.state.Connection` state
      machine.
    - A :trait:`flare.quic.cc.CongestionController` carrier
      (CUBIC in production, Reno in deterministic tests).
    - A :class:`flare.tls.rustls_quic.RustlsQuicSession`
      carrying the per-encryption-level keys + handshake state.

    The reactor's per-packet hot path runs:

    1. Parse the long/short header out of the datagram
       (``flare.quic.packet``) -- done in
       :meth:`QuicListener.dispatch_datagram`.
    2. Decrypt the protected payload via OpenSSL AEAD (Initial)
       or rustls (Handshake / 1-RTT).
    3. Dispatch each frame in the decrypted payload through
       :func:`flare.quic.state.handle_frame_buf`, which advances
       the per-stream + per-connection state machines.
    4. Drive the CC controller with any newly-ACKed bytes.
    5. Build any reply packets the state machine queued and
       feed them to the rustls session for encryption.
    """

    var conn: Connection
    """Sans-I/O connection state. Carries per-stream state +
    flow-control accounting + handshake-complete flag."""

    var local_cid: ConnectionId
    """The Connection ID the server chose for this connection
    (RFC 9000 §5.1). Routed-on by the reactor's CID->connection
    dispatch table."""

    var peer_cid: ConnectionId
    """The Connection ID the client picked for incoming
    server-to-client packets."""

    var cc_choice: Int
    """Which congestion controller this connection runs (RENO
    or CUBIC). Materialized monomorphically by the reactor at
    bind time."""

    var alive: Bool
    """Whether the connection is still in HANDSHAKE / ESTABLISHED
    state. Goes False once the state machine advances to CLOSING
    / DRAINING / CLOSED so the reactor's dispatch table can
    sweep the entry."""

    var idle_timer_id: UInt64
    """Timer-wheel id of the currently-scheduled idle-timeout
    entry (0 if none). Each `handle_packet` call cancels the
    previous idle timer and schedules a fresh one. Stored here
    so the reactor can find and cancel it on connection close."""

    var pto_timer_id: UInt64
    """Timer-wheel id of the currently-scheduled PTO (probe
    timeout) entry. Re-armed on every ack-eliciting send +
    cleared on every ACK that retires the relevant packet
    number space."""

    var ack_delay_timer_id: UInt64
    """Timer-wheel id of the currently-deferred ACK timer. Set
    when ``conn.ack_pending`` flips True; cleared when the ACK
    is actually emitted."""

    var cc_state: CcState
    """Per-connection congestion-controller state. Drives the
    cwnd + pacing budget via the pure functions in
    :mod:`flare.quic.cc`. Initialized via :func:`cc_init` with
    RFC 9002 §B.2 defaults; the reactor hands per-ACK +
    per-loss samples in through :meth:`update_on_ack` /
    :meth:`update_on_loss`."""

    var last_send_us: UInt64
    """Wall-clock timestamp (microseconds) of the most-recent
    send-path tick on this connection. Used by the pacing
    budget calculation: the reactor's egress path calls
    :meth:`pacing_budget(now_us)` and the helper subtracts
    ``last_send_us`` to get the elapsed delta the pure
    :func:`flare.quic.cc.pacing_budget` function consumes."""

    var rx_handshake_secret: List[UInt8]
    """Inbound Handshake-level readiness marker (RFC 9001 §5.1).
    Stamped with the readiness sentinel once rustls installs the
    Handshake keys. Empty until set: Handshake packets that
    arrive while the slot is empty drop silently (the peer will
    retransmit)."""

    var tx_handshake_secret: List[UInt8]
    """Outbound Handshake-level readiness marker. Stamped in
    lockstep with :attr:`rx_handshake_secret`; gates the
    Handshake egress builder."""

    var rx_1rtt_secret: List[UInt8]
    """Inbound 1-RTT readiness marker. Stamped once rustls
    reports handshake-complete. Empty until then; short-header
    packets dropped silently."""

    var tx_1rtt_secret: List[UInt8]
    """Outbound 1-RTT traffic secret. Populated alongside
    :attr:`rx_1rtt_secret`."""

    var tx_initial_pn: UInt64
    """Next packet number to use on the outbound Initial path.
    Monotonic per RFC 9001 §5.3; incremented after every
    successful Initial send. Read + bumped when draining
    :attr:`QuicListener.tls_egress_queues` onto the wire."""

    var tx_initial_offset: UInt64
    """Cumulative offset of CRYPTO bytes the server has emitted
    at the Initial encryption level. Per RFC 9000 §19.6 each
    CRYPTO frame carries its starting offset; this counter
    advances by the byte length of every emitted CRYPTO frame
    so the peer can reassemble the TLS stream in order."""

    var tx_handshake_pn: UInt64
    """Next packet number to use on the outbound Handshake
    path."""

    var tx_handshake_offset: UInt64
    """Cumulative CRYPTO offset at the Handshake level."""

    var tx_1rtt_pn: UInt64
    """Next packet number to use on the outbound 1-RTT path."""

    def __init__(
        out self,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        cc_choice: Int = CcChoice.CUBIC,
        idle_timeout_us: UInt64 = UInt64(30_000_000),
        initial_max_data: UInt64 = UInt64(1 << 20),
    ):
        self.conn = new_connection(idle_timeout_us, initial_max_data)
        self.local_cid = local_cid.copy()
        self.peer_cid = peer_cid.copy()
        self.cc_choice = cc_choice
        self.alive = True
        self.idle_timer_id = UInt64(0)
        self.pto_timer_id = UInt64(0)
        self.ack_delay_timer_id = UInt64(0)
        self.cc_state = cc_init()
        self.last_send_us = UInt64(0)
        self.rx_handshake_secret = List[UInt8]()
        self.tx_handshake_secret = List[UInt8]()
        self.rx_1rtt_secret = List[UInt8]()
        self.tx_1rtt_secret = List[UInt8]()
        self.tx_initial_pn = UInt64(0)
        self.tx_initial_offset = UInt64(0)
        self.tx_handshake_pn = UInt64(0)
        self.tx_handshake_offset = UInt64(0)
        self.tx_1rtt_pn = UInt64(0)

    def install_handshake_keys(
        mut self,
        var rx_secret: List[UInt8],
        var tx_secret: List[UInt8],
    ):
        """Install per-direction Handshake traffic secrets
        (RFC 9001 §5.1), called when rustls emits its first
        ``KeyChange::Handshake``."""
        self.rx_handshake_secret = rx_secret^
        self.tx_handshake_secret = tx_secret^

    def install_1rtt_keys(
        mut self,
        var rx_secret: List[UInt8],
        var tx_secret: List[UInt8],
    ):
        """Install per-direction 1-RTT (application) traffic
        secrets, called on rustls's ``KeyChange::OneRtt`` -- the
        handshake-complete moment."""
        self.rx_1rtt_secret = rx_secret^
        self.tx_1rtt_secret = tx_secret^

    def on_idle_expired(mut self):
        """RFC 9000 §10.1.2 -- silent close on idle timeout.

        The state machine advances to ``CLOSED`` without emitting
        a CONNECTION_CLOSE frame (the peer must come to the same
        conclusion via its own idle timer). The reactor sweeps
        the slot on the next tick.
        """
        self.alive = False
        self.conn.state = CONN_STATE_CLOSED
        self.idle_timer_id = UInt64(0)

    def on_pto_expired(mut self):
        """RFC 9002 §6.2 -- the PTO timer fired. The state
        machine flags that a probe packet is owed; the egress
        path sends one or two PING / PADDING packets so the
        peer's ACK recovers the lost packet-number space."""
        self.pto_timer_id = UInt64(0)
        self.conn.ack_pending = True  # forces an ACK on the next send

    def on_ack_delay_expired(mut self):
        """RFC 9000 §13.2.1 -- the deferred-ACK timer fired.
        The next send is forced to include the pending ACK so
        the peer's RTT estimate stays current."""
        self.ack_delay_timer_id = UInt64(0)
        self.conn.ack_pending = True

    # -- Congestion-control + pacing drive ------------------------------

    def update_on_ack(
        mut self,
        acked_bytes: UInt64,
        rtt_us: UInt64,
        now_us: UInt64,
    ) -> UInt64:
        """Advance the congestion-controller state in response to
        an ACK that acknowledged ``acked_bytes`` of in-flight
        payload at time ``now_us`` with RTT sample ``rtt_us``.

        Delegates to the pure
        :func:`flare.quic.cc.on_ack_received` function, which
        dispatches between slow-start / CUBIC congestion-
        avoidance / HyStart++ exit per RFC 9438 + RFC 9406.
        Returns the new cwnd in bytes.
        """
        return on_ack_received(self.cc_state, acked_bytes, rtt_us, now_us)

    def update_on_loss(mut self, lost_bytes: UInt64, now_us: UInt64) -> UInt64:
        """Apply a loss event: shrink cwnd per the CC's loss
        response (Reno: cwnd /= 2; CUBIC: cwnd *= 0.7) and reset
        the slow-start exit threshold. Returns the new cwnd."""
        return on_packets_lost(self.cc_state, lost_bytes, now_us)

    def on_packet_sent_bytes(mut self, bytes: UInt64, now_us: UInt64):
        """Update the in-flight accounting + pacing timestamp
        when the egress path actually sends ``bytes`` of payload.
        Wraps :func:`flare.quic.cc.on_packet_sent`; the
        ``last_send_us`` carrier is the seam the next
        :meth:`pacing_budget` call subtracts against."""
        on_packet_sent(self.cc_state, bytes)
        self.last_send_us = now_us

    def pacing_budget(self, now_us: UInt64) -> UInt64:
        """Bytes the egress path is allowed to send right now
        under the CC's pacing rate.

        ``now_us`` is the current wall-clock; the helper
        subtracts the connection's :attr:`last_send_us` to get
        the elapsed-since-last-send delta the pure
        :func:`flare.quic.cc.pacing_budget` function consumes.
        Sub-millisecond elapsed values (e.g. 10 us at 12 Mbps
        cwnd produces 15 bytes of budget) round-trip cleanly --
        the underlying multiply happens in nanoseconds inside
        the pure function so precision is not lost.
        """
        if self.last_send_us == UInt64(0) or now_us < self.last_send_us:
            return self.cc_state.mss
        var elapsed_us = now_us - self.last_send_us
        return pacing_budget(self.cc_state, elapsed_us)

    def handle_packet(
        mut self,
        datagram: Span[UInt8, _],
        now_us: UInt64,
        aead_choice: Int = QuicAead.AES_128_GCM,
    ) raises -> ConnectionEvents:
        """Drive one inbound datagram through the per-packet
        decrypt + frame dispatch pipeline.

        Dispatch by encryption level:

        - Long-header Initial: always handled -- the secret is
          derived from the connection's ``local_cid`` (RFC 9001
          §5.2). This is the first-flight path.
        - Long-header Handshake: handled iff
          :attr:`rx_handshake_secret` is non-empty.
        - Short-header 1-RTT: handled iff :attr:`rx_1rtt_secret`
          is non-empty.
        - Long-header 0-RTT + Retry: not handled (flare does not
          accept 0-RTT, and Retry is server-emit-only so it
          never arrives at this path).

        For each handled level the decrypted frame bytes feed
        :func:`flare.quic.state.handle_frame_buf`, which advances
        the sans-I/O state machine and reports back through
        :class:`flare.quic.state.ConnectionEvents`. Packets at a
        level whose secret is not yet installed are dropped
        silently (the peer's PTO-driven retransmission will
        re-deliver once the secret arrives).
        """
        var events = empty_events()
        if len(datagram) < 1:
            return events^
        var first = Int(datagram[0])
        var is_long = (first & 0x80) != 0
        if not is_long:
            return self._handle_1rtt_packet(datagram, now_us, aead_choice)
        var lh: LongHeader
        try:
            lh = parse_long_header(datagram)
        except:
            return events^
        if lh.packet_type == PACKET_TYPE_INITIAL:
            return self._handle_initial_packet(datagram, now_us, aead_choice)
        if lh.packet_type == PACKET_TYPE_HANDSHAKE:
            return self._handle_handshake_packet(datagram, now_us, aead_choice)
        # 0-RTT (1) and Retry (3) are not handled here -- see
        # docstring.
        return events^

    def _handle_initial_packet(
        mut self,
        datagram: Span[UInt8, _],
        now_us: UInt64,
        aead_choice: Int,
    ) raises -> ConnectionEvents:
        """Per-level Initial decrypt + frame dispatch. Carved out
        of :meth:`handle_packet` so the H + 1-RTT branches stay
        readable; behaviour is byte-identical to the v0.8 close-
        wire-paths version."""
        var events = empty_events()
        var up = unprotect_initial_packet(
            datagram,
            self.local_cid,
            is_server=True,
            largest_received_pn=self.conn.largest_received_packet,
            aead_choice=aead_choice,
        )
        var cursor = 0
        var payload = Span[UInt8, _](up.payload)
        while cursor < len(payload):
            var consumed = handle_frame_buf(
                self.conn, payload[cursor:], now_us, events
            )
            if consumed <= 0:
                break
            cursor += consumed
        if up.packet_number > self.conn.largest_received_packet:
            self.conn.largest_received_packet = up.packet_number
        return events^

    def _handle_handshake_packet(
        mut self,
        datagram: Span[UInt8, _],
        now_us: UInt64,
        aead_choice: Int,
    ) raises -> ConnectionEvents:
        """Per-level Handshake decrypt + frame dispatch.

        Returns empty events until :attr:`rx_handshake_secret` is
        installed. The listener now decrypts post-Initial packets
        through rustls; this OpenSSL path is retained for unit
        tests that exercise the sans-I/O connection directly.
        """
        var events = empty_events()
        if len(self.rx_handshake_secret) == 0:
            return events^
        var up = unprotect_handshake_packet(
            datagram,
            Span[UInt8, _](self.rx_handshake_secret),
            self.conn.largest_received_packet,
            aead_choice=aead_choice,
        )
        var cursor = 0
        var payload = Span[UInt8, _](up.payload)
        while cursor < len(payload):
            var consumed = handle_frame_buf(
                self.conn, payload[cursor:], now_us, events
            )
            if consumed <= 0:
                break
            cursor += consumed
        if up.packet_number > self.conn.largest_received_packet:
            self.conn.largest_received_packet = up.packet_number
        return events^

    def _handle_1rtt_packet(
        mut self,
        datagram: Span[UInt8, _],
        now_us: UInt64,
        aead_choice: Int,
    ) raises -> ConnectionEvents:
        """Per-level 1-RTT decrypt + frame dispatch.

        Returns empty events until :attr:`rx_1rtt_secret` is
        installed. ``dcid_length`` comes from the connection's
        pinned ``local_cid`` length -- a short header carries the
        DCID bytes but not its length (RFC 9000 §17.3), so the
        receiver supplies it from per-connection state. Retained
        for unit tests; the listener decrypts 1-RTT via rustls.
        """
        var events = empty_events()
        if len(self.rx_1rtt_secret) == 0:
            return events^
        var up = unprotect_1rtt_packet(
            datagram,
            Span[UInt8, _](self.rx_1rtt_secret),
            self.conn.largest_received_packet,
            self.local_cid.length(),
            aead_choice=aead_choice,
        )
        var cursor = 0
        var payload = Span[UInt8, _](up.payload)
        while cursor < len(payload):
            var consumed = handle_frame_buf(
                self.conn, payload[cursor:], now_us, events
            )
            if consumed <= 0:
                break
            cursor += consumed
        if up.packet_number > self.conn.largest_received_packet:
            self.conn.largest_received_packet = up.packet_number
        return events^

    def dispatch_plaintext(
        mut self,
        plaintext: Span[UInt8, _],
        now_us: UInt64,
        packet_number: UInt64,
    ) raises -> ConnectionEvents:
        """Drive already-decrypted frame bytes through the
        sans-I/O state machine.

        The listener decrypts Handshake + 1-RTT packets through
        the rustls session (which holds the real AEAD keys) and
        hands the plaintext here, since the sans-I/O connection
        has no rustls handle. Mirrors the frame-dispatch loop in
        the per-level handlers minus the decrypt step.
        """
        var events = empty_events()
        var cursor = 0
        while cursor < len(plaintext):
            var consumed = handle_frame_buf(
                self.conn, plaintext[cursor:], now_us, events
            )
            if consumed <= 0:
                break
            cursor += consumed
        if packet_number > self.conn.largest_received_packet:
            self.conn.largest_received_packet = packet_number
        return events^


# -- Connection ID table ------------------------------------------------


struct ConnectionIdTable(Copyable, Defaultable, Movable, Sized):
    """Per-listener routing table from Connection ID to connection.

    QUIC routes inbound datagrams to the right connection via
    the Destination Connection ID in the packet header (RFC 9000
    §5.1). The table maps each issued CID (server-side: the
    local_cid from :class:`QuicConnection`; client-side: the
    Source Connection IDs the server sent in NEW_CONNECTION_ID
    frames) to the connection slot it belongs to.

    The carrier uses :class:`Dict[String, Int]` where the key is
    the lowercase-hex CID and the value is the slot index into
    the listener's connection slab.
    """

    var cid_to_slot: Dict[String, Int]
    """CID (lowercase-hex of CID bytes) -> slot index. Empty
    string is invalid; a connection can have up to
    `active_connection_id_limit` (RFC 9000 §18.2) CIDs at once,
    each pointing at the same slot."""

    def __init__(out self):
        self.cid_to_slot = Dict[String, Int]()

    def register(mut self, cid_hex: String, slot: Int):
        """Add a CID -> slot mapping. Idempotent: overwriting
        an existing mapping is allowed (the server may reissue
        CIDs after migration)."""
        self.cid_to_slot[cid_hex] = slot

    def lookup(self, cid_hex: String) raises -> Int:
        """Look up the slot for a CID. Returns -1 if absent.
        The reactor uses -1 to gate the Initial packet path
        (no slot -> potentially new connection -> run the
        accept-handshake state machine)."""
        if cid_hex in self.cid_to_slot:
            return self.cid_to_slot[cid_hex]
        return -1

    def retire(mut self, cid_hex: String) raises:
        """Drop a CID -> slot mapping. Called when the connection
        retires a CID via RETIRE_CONNECTION_ID (RFC 9000 §19.16)
        or when the connection itself closes."""
        if cid_hex in self.cid_to_slot:
            _ = self.cid_to_slot.pop(cid_hex)

    def __len__(self) -> Int:
        return len(self.cid_to_slot)


# -- CID hex helper (used by the dispatch table key) -------------------


@always_inline
def _hex_nibble(n: Int) -> UInt8:
    """Return the lowercase ASCII byte for a single hex nibble."""
    if n < 10:
        return UInt8(48 + n)  # '0'..'9'
    return UInt8(87 + n)  # 'a'..'f'


def cid_to_hex(cid: ConnectionId) -> String:
    """Encode a CID's bytes as lowercase hex. Used by the
    dispatch table key so :class:`ConnectionIdTable` can hash
    on a plain :class:`String`. An empty CID returns the empty
    string -- the routing layer rejects that case explicitly.
    """
    var out = List[UInt8]()
    for i in range(len(cid.bytes)):
        var b = Int(cid.bytes[i])
        out.append(_hex_nibble((b >> 4) & 0xF))
        out.append(_hex_nibble(b & 0xF))
    out.append(UInt8(0))  # null terminator for String constructor
    return String(unsafe_from_utf8=Span[UInt8, _](out[: len(out) - 1]))


# -- Listener -----------------------------------------------------------


struct QuicListener(Movable):
    """UDP listener + per-connection dispatcher.

    Long-lived. One instance per QUIC server bind. Construct via
    :meth:`bind`; the constructor opens the UDP socket and binds
    it. The reactor drives the listener via :meth:`run` (blocks
    until :meth:`shutdown`) or :meth:`tick` (single iteration --
    used by tests + by callers that want to multiplex the event
    loop with other work).
    """

    var config: QuicServerConfig
    var cid_table: ConnectionIdTable
    var connections: List[QuicConnection]
    """Connection slab. Per-connection state lives here; the
    :class:`ConnectionIdTable` maps each Connection ID to the
    slot index. Slots are append-only; the closed-slot sweeper
    runs at the end of every :meth:`advance_timers` call so
    timer-fired connections (idle, PTO-exhausted) get reaped
    against the same monotonic clock the wheel uses."""
    var tls_acceptor: RustlsQuicAcceptor
    """Long-lived rustls QUIC acceptor built once at
    :meth:`bind` from :attr:`QuicServerConfig.rustls_config`.
    Owns the rustls ``ServerConfig`` (cert + key + ALPN list)
    that every per-connection session derives keys from. When
    the caller passes the default (empty PEM)
    :class:`RustlsQuicConfig`, the FFI returns a NULL handle and
    the dispatch path routes all CRYPTO frames through the
    silent-drop branch -- existing tests that bind a listener
    purely to exercise the UDP / routing / timer surfaces
    continue to work without supplying real PEM material."""
    var tls_sessions: List[_SessionSlot]
    """Parallel slab to :attr:`connections`: one rustls QUIC
    session carrier per :class:`QuicConnection` slot. Each
    :class:`_SessionSlot` holds the raw rustls
    ``Box<Session>*`` (or 0 for the NULL-PEM sentinel) plus the
    current outbound encryption level. The slab owns the
    handles; :meth:`__del__` walks every non-zero handle through
    :func:`flare.tls._rustls_quic_ffi._do_session_free` exactly
    once at listener teardown. The shared FFI library handle for
    every per-slot call is borrowed from
    :attr:`tls_acceptor._lib` so the .so stays mapped across
    every feed-crypto / take-crypto roundtrip."""
    var tls_egress_queues: List[List[UInt8]]
    """Per-slot outbound CRYPTO byte queue at the INITIAL level.
    Each successful :meth:`feed_crypto` is followed by
    :meth:`take_crypto` and the resulting bytes append here;
    :meth:`_drain_and_send` wraps them in a CRYPTO frame inside an
    Initial-level packet, AEAD-protects with
    :func:`protect_initial_packet`, and emits via :meth:`send_to`.
    Cleared after every successful drain."""
    var tls_handshake_egress_queues: List[List[UInt8]]
    """Per-slot outbound CRYPTO byte queue at the HANDSHAKE
    level. Populated by :meth:`_dispatch_crypto_frames` after
    rustls emits ``KeyChange::Handshake``. Drained by the egress
    builder which wraps each batch in a CRYPTO frame inside a
    Handshake-level packet, AEAD-protects via
    :class:`RustlsQuicSession.packet_encrypt` at level 2, and
    emits via :meth:`send_to`."""
    var tls_1rtt_egress_queues: List[List[UInt8]]
    """Per-slot outbound CRYPTO byte queue at the 1-RTT
    (APPLICATION) level. Populated by
    :meth:`_dispatch_crypto_frames` after rustls emits
    ``KeyChange::OneRtt``. Drained by the egress builder which
    encodes each batch into a 1-RTT short-header packet,
    AEAD-protects via :class:`RustlsQuicSession.packet_encrypt`
    at level 3, and emits via :meth:`send_to`."""
    var peer_addrs: List[SocketAddr]
    """Per-slot peer UDP address. Parallel slab to
    :attr:`connections` -- captured in :meth:`_accept_initial`
    from the inbound datagram's sender. The egress path reads
    this to call :meth:`send_to(slot, ...)` without re-parsing
    the inbound datagram."""
    var h3_connections: List[H3Connection]
    """Per-slot HTTP/3 connection driver. Parallel slab to
    :attr:`connections` -- one :class:`flare.h3.H3Connection`
    instance per QUIC connection. Allocated in
    :meth:`_accept_initial` so every accepted connection has its
    H3 driver ready; STREAM frames from the post-handshake 1-RTT
    payload route through :meth:`_route_h3_stream_chunks` into
    the matching slot.

    The slab carries the H3 driver unconditionally rather than
    waiting for the ``h3`` ALPN to be negotiated. The QUIC
    layer cannot inspect ALPN without finishing the rustls
    handshake and we want the slab indices to stay in lockstep
    with :attr:`connections`. The H3 driver itself drops
    non-H3 traffic (the STREAM frames simply never reach
    :meth:`H3Connection.feed_stream_chunk` until 1-RTT keys
    install, at which point the peer already negotiated H3 via
    ALPN by definition)."""
    var h3_response_egress: Dict[String, List[UInt8]]
    """Per-(slot, stream_id) outbound H3 response bytes,
    awaiting QUIC STREAM frame egress. Key is
    ``str(slot) + ":" + str(stream_id)``; value is the byte
    buffer emitted by
    :meth:`flare.h3.H3Connection.take_response_frames` after a
    handler-produced :class:`Response` is encoded. Drained by
    the 1-RTT egress path once the per-connection 1-RTT keys
    are installed."""
    var timer_wheel: TimerWheel
    """Per-listener :class:`flare.runtime.timer_wheel.TimerWheel`
    driving PTO / idle / ack-delay timeouts. Each scheduled
    timer's token is
    :func:`flare.quic.timers.encode_timer_token(kind, slot)`;
    :meth:`advance_timers` dispatches each fired token to the
    matching :class:`QuicConnection` callback."""
    var _socket: UdpSocket
    var _local_addr: SocketAddr
    var _stopping: Bool
    """Set by :meth:`shutdown`. Read by :meth:`run` at the top of
    every loop iteration so the event loop exits cleanly after
    the next ``recv_from`` returns or times out."""

    def __init__(
        out self,
        config: QuicServerConfig,
        var sock: UdpSocket,
        addr: SocketAddr,
        var tls_acceptor: RustlsQuicAcceptor,
    ):
        """Wrap an already-bound :class:`UdpSocket`. Internal --
        callers use :meth:`bind`."""
        self.config = config.copy()
        self.cid_table = ConnectionIdTable()
        self.connections = List[QuicConnection]()
        self.tls_acceptor = tls_acceptor^
        self.tls_sessions = List[_SessionSlot]()
        self.tls_egress_queues = List[List[UInt8]]()
        self.tls_handshake_egress_queues = List[List[UInt8]]()
        self.tls_1rtt_egress_queues = List[List[UInt8]]()
        self.peer_addrs = List[SocketAddr]()
        self.h3_connections = List[H3Connection]()
        self.h3_response_egress = Dict[String, List[UInt8]]()
        self.timer_wheel = TimerWheel(now_ms=UInt64(0))
        self._socket = sock^
        self._local_addr = addr
        self._stopping = False

    def __del__(deinit self):
        """Drop the listener: release every rustls session in
        the slab exactly once.

        Each :class:`_SessionSlot` is a non-owning carrier; the
        slab itself is the unique owner of the underlying
        ``Box<Session>*`` allocations rustls produced via
        :func:`_do_accept`. The free routes through
        :meth:`RustlsQuicAcceptor.free_session` so Mojo's
        ``deinit`` rule (no sub-field access during ``deinit``)
        is respected -- the acceptor borrows ``self`` (and its
        ``_lib``) by reference rather than via a sub-field of
        the listener.
        """
        for i in range(len(self.tls_sessions)):
            var h = self.tls_sessions[i].handle
            if h != 0:
                self.tls_acceptor.free_session(h)

    @staticmethod
    def bind(config: QuicServerConfig) raises -> QuicListener:
        """Open the UDP socket and bind it to ``config.host`` /
        ``config.port``. Returns a ready-to-run listener.

        If ``config.port == 0`` the kernel picks an ephemeral
        port; read it back via :meth:`local_addr`.

        Constructs the per-listener rustls QUIC acceptor from
        ``config.rustls_config`` at bind time so each accepted
        connection's TLS session is materialized against the
        same long-lived ``ServerConfig``. An empty / malformed
        PEM does not raise here; the acceptor
        surfaces a NULL handle and CRYPTO bytes route through
        the silent-drop branch.
        """
        var ip = IpAddr.parse(config.host)
        var addr = SocketAddr(ip, config.port)
        var sock = UdpSocket.bind(addr)
        var actual = sock.local_addr()
        var acceptor = RustlsQuicAcceptor(config.rustls_config.copy())
        return QuicListener(config, sock^, actual, acceptor^)

    def local_addr(self) -> SocketAddr:
        """Return the address the UDP socket is actually bound to.
        After :meth:`bind` with ``config.port == 0`` this reports
        the kernel-chosen ephemeral port."""
        return self._local_addr

    def bound(self) -> Bool:
        """Whether the UDP socket is bound. True for every
        listener returned by :meth:`bind`."""
        return True

    def connection_count(self) -> Int:
        """Number of connection slots currently allocated."""
        return len(self.connections)

    def dispatch_datagram(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises -> Int:
        """Route a single UDP datagram to the right connection slot.

        Parses the first byte to pick long vs short header,
        extracts the Destination Connection ID, looks it up in
        :attr:`cid_table`, and either:

        * Routes the datagram to the existing slot via
          :meth:`_handle_inbound`. Decryption failures are caught
          and converted to silent drops so a single bad sender
          can't poison the listener.
        * Allocates a new slot for an Initial packet with an
          unknown DCID (the QUIC accept path -- RFC 9000 §7),
          then drives the same inbound path on the new connection
          so the first Initial advances the state machine.
        * Returns ``-1`` to drop short-header packets with
          unknown DCIDs (those datagrams are silently
          discarded).
        """
        if len(datagram) < 1:
            return -1
        var first = Int(datagram[0])
        var is_long = (first & 0x80) != 0
        var slot: Int
        if is_long:
            slot = self._dispatch_long(datagram, peer)
        else:
            slot = self._dispatch_short(datagram, peer)
        if slot >= 0 and slot < len(self.connections):
            self._handle_inbound(slot, datagram)
        return slot

    def _handle_inbound(mut self, slot: Int, datagram: Span[UInt8, _]) raises:
        """Decrypt + dispatch one inbound datagram by encryption
        level.

        Initial packets decrypt off the DCID-derived secret in
        the sans-I/O connection. Handshake + 1-RTT packets carry
        keys rustls keeps sealed, so they decrypt through the
        slot's rustls session here (the listener owns the FFI
        handle) and the plaintext drives the state machine via
        :meth:`QuicConnection.dispatch_plaintext`.

        Decrypt and frame-parse failures drop silently per
        RFC 9001 sec 5.2; the slot stays alive for retransmits.
        On success, inbound CRYPTO bytes feed rustls via
        :meth:`_dispatch_crypto_frames` and the idle timer re-arms.
        """
        var now_us = UInt64(0)
        var inbound_lvl = _inbound_level_for_datagram(datagram)
        var conn = self.connections[slot].copy()
        var events = empty_events()
        var ok = True
        if inbound_lvl == QuicEncryptionLevel.INITIAL:
            try:
                events = conn.handle_packet(datagram, now_us)
            except:
                ok = False
        elif inbound_lvl == QuicEncryptionLevel.HANDSHAKE:
            if len(conn.rx_handshake_secret) == 0:
                ok = False  # keys not installed yet; drop
            else:
                try:
                    var dec = self._decrypt_post_initial(
                        slot,
                        datagram,
                        inbound_lvl,
                        conn.local_cid.length(),
                    )
                    events = conn.dispatch_plaintext(
                        Span[UInt8, _](dec[0]), now_us, dec[1]
                    )
                except:
                    ok = False
        elif inbound_lvl == QuicEncryptionLevel.APPLICATION:
            if len(conn.rx_1rtt_secret) == 0:
                ok = False
            else:
                try:
                    var dec = self._decrypt_post_initial(
                        slot,
                        datagram,
                        inbound_lvl,
                        conn.local_cid.length(),
                    )
                    events = conn.dispatch_plaintext(
                        Span[UInt8, _](dec[0]), now_us, dec[1]
                    )
                except:
                    ok = False
        else:
            ok = False  # 0-RTT / Retry not handled here
        self.connections[slot] = conn^
        if not ok:
            return
        self._dispatch_crypto_frames(slot, events, inbound_lvl)
        self._route_h3_stream_chunks(slot, events)
        _ = self.schedule_idle_timeout(slot)

    def _decrypt_post_initial(
        mut self,
        slot: Int,
        datagram: Span[UInt8, _],
        level: Int,
        dcid_length: Int,
    ) raises -> Tuple[List[UInt8], UInt64]:
        """Strip header protection + AEAD-decrypt a Handshake or
        1-RTT datagram through the slot's rustls session, which
        owns the real per-level keys.

        Returns ``(plaintext, packet_number)``. Raises on any
        bounds, FFI, or AEAD failure so the caller drops the
        packet (RFC 9001 sec 5.2).

        Header protection: rustls's ``decrypt_in_place`` unmasks
        the first byte, derives the packet-number length from it,
        then XORs only that many bytes of the supplied slice. A
        4-byte scratch copy of the pn region is therefore safe --
        only ``pn_length`` bytes are touched, the rest discarded,
        and the datagram bytes are never mutated.
        """
        if slot < 0 or slot >= len(self.tls_sessions):
            raise Error("_decrypt_post_initial: slot out of range")
        var handle = self.tls_sessions[slot].handle
        if handle == 0:
            raise Error("_decrypt_post_initial: NULL session handle")
        var pn_offset: Int
        if level == QuicEncryptionLevel.HANDSHAKE:
            pn_offset = parse_long_header(datagram).payload_offset
        else:
            pn_offset = parse_short_header(datagram, dcid_length).payload_offset
        # The HP sample sits 4 bytes past the pn field start
        # (RFC 9001 sec 5.4.2); that window must fit the datagram.
        var sample_offset = pn_offset + 4
        if sample_offset + 16 > len(datagram):
            raise Error(
                "_decrypt_post_initial: HP sample window exceeds packet"
            )
        var sample = List[UInt8]()
        for i in range(16):
            sample.append(datagram[sample_offset + i])
        # Scratch the first byte + 4 candidate pn bytes; rustls
        # unmasks first, reads pn_length, XORs only that many.
        var first_local: UInt8 = datagram[0]
        var pn_local = List[UInt8]()
        for i in range(4):
            pn_local.append(datagram[pn_offset + i])
        var first_addr = Int(UnsafePointer(to=first_local))
        _do_header_decrypt(
            self.tls_acceptor._lib,
            handle,
            level,
            sample,
            first_addr,
            Int(pn_local.unsafe_ptr()),
            4,
        )
        var pn_length = (Int(first_local) & 0x03) + 1
        var truncated_pn = UInt64(0)
        for i in range(pn_length):
            truncated_pn = (truncated_pn << 8) | UInt64(pn_local[i])
        var packet_number = decode_packet_number(
            truncated_pn,
            pn_length,
            self.connections[slot].conn.largest_received_packet,
        )
        # AAD is the unprotected header: first byte + bytes up to
        # the pn field + the pn_length real pn bytes.
        var header = List[UInt8]()
        header.append(first_local)
        for i in range(1, pn_offset):
            header.append(datagram[i])
        for i in range(pn_length):
            header.append(pn_local[i])
        var ciphertext_start = pn_offset + pn_length
        var payload = List[UInt8]()
        for i in range(ciphertext_start, len(datagram)):
            payload.append(datagram[i])
        var plaintext_len = _do_packet_decrypt(
            self.tls_acceptor._lib,
            handle,
            level,
            packet_number,
            header,
            payload,
        )
        var plaintext = List[UInt8]()
        for i in range(plaintext_len):
            plaintext.append(payload[i])
        return (plaintext^, packet_number)

    def _dispatch_crypto_frames(
        mut self, slot: Int, events: ConnectionEvents, inbound_lvl: Int
    ) raises:
        """Forward inbound CRYPTO frame bytes to the slot's
        rustls QUIC session, drain outbound CRYPTO bytes at
        EVERY encryption level into the per-slot egress queue,
        and -- after each drain -- check whether rustls's
        `KeyChange` pump has just installed Handshake or 1-RTT
        keys on the slot's session.  When the keys at a level
        flip from None to Some(_) we stamp a sentinel onto the
        connection's per-level secret carrier so the
        post-Initial decrypt path flips from "drop silently" to
        "dispatch via rustls".

        The Mojo side does NOT carry raw traffic secrets --
        rustls's `quic::Secrets` is `pub(crate)`-sealed. The
        carriers :attr:`QuicConnection.rx_handshake_secret` /
        `.tx_handshake_secret` / `.rx_1rtt_secret` /
        `.tx_1rtt_secret` are reused as boolean readiness
        markers: empty list == not installed; non-empty list
        (length 1, contents `0xff`) == installed and the rustls
        session has the keys.

        Both the feed-crypto and take-crypto FFI calls route
        through :attr:`tls_acceptor._lib` so the .so stays
        mapped across the call (Mojo's ASAP destructor cannot
        unmap the library between symbol resolution and the
        thunk).
        """
        if slot < 0 or slot >= len(self.tls_sessions):
            return
        var handle = self.tls_sessions[slot].handle
        if handle == 0:
            return

        # Feed inbound CRYPTO frame bytes at the level the
        # parent _handle_inbound just decrypted at. All CRYPTO
        # frames in a single ConnectionEvents batch belong to
        # the same encryption level (the level of the parent
        # packet); QUIC explicitly forbids mixing CRYPTO levels
        # across packets at the protocol layer (RFC 9001
        # §4.1.3), so the caller supplies the level rather than
        # the sans-I/O state machine carrying a per-frame tag.
        for i in range(len(events.crypto_frames)):
            var chunk = List[UInt8]()
            for j in range(len(events.crypto_frames[i].data)):
                chunk.append(events.crypto_frames[i].data[j])
            var rc = _do_feed_crypto(
                self.tls_acceptor._lib, handle, inbound_lvl, chunk
            )
            if rc != 0:
                # rustls rejected the bytes (bad TLS grammar) --
                # silent drop per RFC 9001 §5.2. The session
                # level does not advance, which is what the
                # post-Initial gating below reads.
                continue

        # Drain rustls's outbound CRYPTO bytes at every level
        # rustls might have buffered for us. The KeyChange-driven
        # pump in `flare_rustls_quic_drain_outbound` routes bytes
        # onto the correct per-level pending queue inside the Rust
        # shim; we just call take_crypto once per level and append.
        try:
            var out_initial = _do_take_crypto(
                self.tls_acceptor._lib,
                handle,
                QuicEncryptionLevel.INITIAL,
            )
            for k in range(len(out_initial)):
                self.tls_egress_queues[slot].append(out_initial[k])
        except:
            pass
        try:
            var out_hs = _do_take_crypto(
                self.tls_acceptor._lib,
                handle,
                QuicEncryptionLevel.HANDSHAKE,
            )
            for k in range(len(out_hs)):
                self.tls_handshake_egress_queues[slot].append(out_hs[k])
        except:
            pass
        try:
            var out_1rtt = _do_take_crypto(
                self.tls_acceptor._lib,
                handle,
                QuicEncryptionLevel.APPLICATION,
            )
            for k in range(len(out_1rtt)):
                self.tls_1rtt_egress_queues[slot].append(out_1rtt[k])
        except:
            pass

        # After every CRYPTO pump, ask rustls whether the
        # KeyChange-driven pump just installed Handshake or
        # 1-RTT keys on this session. The conditional install
        # below is idempotent (stamping the sentinel twice is a
        # no-op): once the level flips, every subsequent call
        # sees `have_keys == True` and we install once.
        var have_hs = (
            _do_have_keys(
                self.tls_acceptor._lib,
                handle,
                QuicEncryptionLevel.HANDSHAKE,
            )
            == 1
        )
        var have_1rtt = (
            _do_have_keys(
                self.tls_acceptor._lib,
                handle,
                QuicEncryptionLevel.APPLICATION,
            )
            == 1
        )
        if have_hs or have_1rtt:
            var conn_copy = self.connections[slot].copy()
            if have_hs and len(conn_copy.rx_handshake_secret) == 0:
                conn_copy.install_handshake_keys(
                    _ready_sentinel(), _ready_sentinel()
                )
            if have_1rtt and len(conn_copy.rx_1rtt_secret) == 0:
                conn_copy.install_1rtt_keys(
                    _ready_sentinel(), _ready_sentinel()
                )
            self.connections[slot] = conn_copy^

    # -- H3 dispatch surface ----------------------------------------------

    def _route_h3_stream_chunks(
        mut self, slot: Int, events: ConnectionEvents
    ) raises:
        """Route every STREAM frame surfaced on ``events`` to the
        slot's :class:`flare.h3.H3Connection`.

        RFC 9114 §6 puts H3 traffic on QUIC bidirectional + uni
        streams; the stream id parity bits classify which kind a
        frame belongs to (RFC 9000 §2.1: even = client-initiated
        bidi / uni based on the low two bits). The H3 driver
        accepts both flavors through different entry points;
        this method picks the right one and also signals FIN
        when the QUIC layer observed end-of-stream.

        No-op if the slot is out of range or no STREAM frames
        were surfaced this tick. Empty payload chunks with FIN
        still drive :meth:`flare.h3.H3Connection.signal_end_of_stream`
        so the H3 driver can advance request state.
        """
        if slot < 0 or slot >= len(self.h3_connections):
            return
        if len(events.stream_chunks) == 0:
            return
        var h3 = self.h3_connections[slot].copy()
        for i in range(len(events.stream_chunks)):
            var sid = Int(events.stream_chunks[i].stream_id)
            var is_uni = (sid & 0x2) != 0
            var is_fin = events.stream_chunks[i].fin
            var payload = events.stream_chunks[i].data.copy()
            if len(payload) > 0:
                if is_uni:
                    h3.feed_uni_stream_chunk(sid, payload^)
                else:
                    h3.feed_stream_chunk(sid, payload^)
            if is_fin and not is_uni:
                h3.signal_end_of_stream(sid)
        self.h3_connections[slot] = h3^

    def take_h3_completed_streams(self, slot: Int) raises -> List[Int]:
        """Return the stream ids ready for handler dispatch on
        ``slot``. Delegates to
        :meth:`flare.h3.H3Connection.take_completed_streams`.
        Empty list if the slot is out of range or has no H3
        driver attached."""
        if slot < 0 or slot >= len(self.h3_connections):
            return List[Int]()
        return self.h3_connections[slot].take_completed_streams()

    def take_h3_request(mut self, slot: Int, stream_id: Int) raises -> Request:
        """Materialize the :class:`flare.http.Request` for
        ``(slot, stream_id)``. The dispatch caller invokes a
        Handler with this Request, then feeds the Response back
        through :meth:`emit_h3_response`.

        Raises if the slot is out of range or the H3 driver
        does not track the stream (see
        :meth:`flare.h3.H3Connection.take_request` for the
        underlying gating)."""
        if slot < 0 or slot >= len(self.h3_connections):
            raise Error(
                "take_h3_request: slot " + String(slot) + " out of range"
            )
        var h3 = self.h3_connections[slot].copy()
        var req = h3.take_request(stream_id)
        self.h3_connections[slot] = h3^
        return req^

    def emit_h3_response(
        mut self, slot: Int, stream_id: Int, var response: Response
    ) raises:
        """Encode ``response`` into the slot's H3 outbox + drain
        the resulting frame bytes into
        :attr:`h3_response_egress` keyed by ``slot:stream_id``.

        The byte buffer feeds the 1-RTT STREAM-frame egress pass
        in :meth:`_drain_h3_response_egress`, which emits on the
        wire once the slot's 1-RTT keys are installed.
        """
        if slot < 0 or slot >= len(self.h3_connections):
            raise Error(
                "emit_h3_response: slot " + String(slot) + " out of range"
            )
        var h3 = self.h3_connections[slot].copy()
        h3.emit_response(stream_id, response^)
        var frames = h3.take_response_frames(stream_id)
        self.h3_connections[slot] = h3^
        var key = String(slot) + ":" + String(stream_id)
        if key in self.h3_response_egress:
            var existing = self.h3_response_egress[key].copy()
            for i in range(len(frames)):
                existing.append(frames[i])
            self.h3_response_egress[key] = existing^
        else:
            self.h3_response_egress[key] = frames^

    def take_h3_response_egress(
        mut self, slot: Int, stream_id: Int
    ) raises -> List[UInt8]:
        """Drain the per-stream response buffer accumulated by
        :meth:`emit_h3_response`. Returns an empty list when no
        bytes are queued. Caller (the QUIC STREAM egress path)
        wraps the bytes in STREAM frames + protects them with
        :func:`protect_1rtt_packet` -- the wiring lands once
        1-RTT keys flow through the rustls bridge."""
        var key = String(slot) + ":" + String(stream_id)
        if key not in self.h3_response_egress:
            return List[UInt8]()
        var out = self.h3_response_egress.pop(key)
        return out^

    def _dispatch_long(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises -> Int:
        """Long-header path: parse the full header, route by DCID,
        and accept an Initial packet against an unknown DCID."""
        var lh: LongHeader
        try:
            lh = parse_long_header(datagram)
        except:
            return -1
        var dcid_hex = cid_to_hex(lh.dcid)
        var slot = self.cid_table.lookup(dcid_hex)
        if slot >= 0:
            return slot
        if lh.packet_type == PACKET_TYPE_INITIAL:
            return self._accept_initial(lh, peer)
        return -1

    def _dispatch_short(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises -> Int:
        """Short-header path: parse with the listener's pinned
        DCID length, route by DCID."""
        var sh_dcid_len = self.config.local_cid_length
        if sh_dcid_len <= 0 or sh_dcid_len > MAX_CID_LENGTH:
            return -1
        var sh = parse_short_header(datagram, sh_dcid_len)
        var dcid_hex = cid_to_hex(sh.dcid)
        return self.cid_table.lookup(dcid_hex)

    def _accept_initial(
        mut self, lh: LongHeader, peer: SocketAddr
    ) raises -> Int:
        """Allocate a new connection slot for an Initial packet
        with an unknown DCID.

        The server registers the client-chosen DCID in
        :attr:`cid_table` so subsequent Initials addressed to
        the same DCID route here. RFC 9000 §7.2 says the server
        SHOULD choose its own SCID and switch to it on the
        server-side response.

        Also materializes the per-slot rustls QUIC session, the
        empty CRYPTO egress queue, the peer UDP address (so the
        egress drain can :meth:`send_to` without re-parsing), and
        arms the per-connection idle timeout.
        """
        var local_cid = lh.dcid.copy()
        var peer_cid = lh.scid.copy()
        var qc = QuicConnection(
            local_cid,
            peer_cid,
            self.config.cc_choice,
            self.config.max_idle_timeout_ms * UInt64(1_000),
            self.config.initial_max_data,
        )
        var slot = len(self.connections)
        self.connections.append(qc^)
        self.tls_sessions.append(self._new_session_slot())
        self.tls_egress_queues.append(List[UInt8]())
        self.tls_handshake_egress_queues.append(List[UInt8]())
        self.tls_1rtt_egress_queues.append(List[UInt8]())
        self.peer_addrs.append(peer)
        self.h3_connections.append(H3Connection())
        self.cid_table.register(cid_to_hex(local_cid), slot)
        _ = self.schedule_idle_timeout(slot)
        return slot

    def _new_session_slot(mut self) -> _SessionSlot:
        """Materialize a per-slot rustls QUIC session.

        Empty-PEM configurations (the default
        :class:`RustlsQuicConfig` shape that the existing test
        suite + fuzz harness rely on) leave the acceptor's
        opaque handle at 0; this method short-circuits to the
        NULL-handle sentinel slot. Production paths with a real
        PEM cert call into :func:`_do_accept` with an empty
        transport-parameters blob; any FFI rejection also falls
        through to the NULL sentinel so the slab stays in
        lockstep with :attr:`connections`.
        """
        if self.tls_acceptor._opaque_handle == 0:
            return _SessionSlot(handle=0, level=QuicEncryptionLevel.INITIAL)
        var empty_tp = List[UInt8]()
        var handle = _do_accept(
            self.tls_acceptor._lib, self.tls_acceptor._opaque_handle, empty_tp
        )
        return _SessionSlot(handle=handle, level=QuicEncryptionLevel.INITIAL)

    def tick(mut self, timeout_ms: Int = 100) raises -> Bool:
        """Drain at most one inbound datagram and pump egress.

        Reactor I/O loop step:

        1. ``recv_from`` -- pull one datagram off the socket (or
           time out cleanly after ``timeout_ms``).
        2. ``dispatch_datagram`` -- route by DCID; the matched
           slot's :meth:`_handle_inbound` advances the sans-I/O
           state machine and surfaces inbound CRYPTO frames; the
           bridge feeds them to rustls and drains outbound CRYPTO
           bytes into :attr:`tls_egress_queues`.
        3. ``drain_all_egress`` -- every slot with pending bytes
           gets a server Initial packet protected via
           :func:`protect_initial_packet` and emitted through
           :meth:`send_to`.

        Returns ``True`` if a datagram was received + dispatched,
        ``False`` if ``recv_from`` timed out. ``timeout_ms`` is
        applied via ``SO_RCVTIMEO``; the default 100 ms is the
        same shutdown-poll cadence :meth:`run` uses.
        """
        self._socket.set_recv_timeout(timeout_ms)
        var buf = List[UInt8]()
        buf.resize(Int(self.config.max_udp_payload_size), 0)
        var sender: SocketAddr
        var got: Int
        try:
            var pair = self._socket.recv_from(Span[UInt8, _](buf))
            got = pair[0]
            sender = pair[1]
        except e:
            # ``UdpSocket.recv_from`` raises :class:`Timeout` for
            # both ``EAGAIN`` and ``EWOULDBLOCK``; the dispatch
            # loop treats both as "no datagram this tick" but
            # still drains pending egress so an already-handshaking
            # session can flush its ServerHello fragments.
            var msg = String(e)
            if msg.startswith("Timeout") or msg.startswith("recvfrom"):
                _ = self.drain_all_egress()
                return False
            raise e^
        if got <= 0:
            _ = self.drain_all_egress()
            return False
        var slot = self.dispatch_datagram(Span[UInt8, _](buf[:got]), sender)
        if slot >= 0:
            _ = self._drain_and_send(slot)
        return True

    def send_to(self, datagram: Span[UInt8, _], addr: SocketAddr) raises -> Int:
        """Emit a single fully-protected QUIC datagram on the
        listener's UDP socket. Thin wrapper over
        :meth:`flare.udp.socket.UdpSocket.send_to` so the
        egress path has the same surface the unit tests stub.
        Returns the byte count actually written (UDP either
        sends the whole datagram or raises)."""
        return self._socket.send_to(datagram, addr)

    def drain_all_egress(mut self) raises -> Int:
        """Drain every slot's :attr:`tls_egress_queues` onto the
        wire. Returns the number of datagrams emitted.

        Called from the reactor between recv ticks (and on the
        ``recv_from`` timeout path) so a slot with pending
        outbound CRYPTO bytes can flush even if no inbound
        datagram arrived. Pure no-op if no slot has pending
        bytes.
        """
        var emitted = 0
        for slot in range(len(self.connections)):
            if self._drain_and_send(slot):
                emitted += 1
        return emitted

    def _drain_and_send(mut self, slot: Int) raises -> Bool:
        """Drain every pending egress queue for ``slot`` onto
        the wire.

        Returns ``True`` if at least one datagram was emitted.
        Per-level queues drained (each is independent and any
        subset can be non-empty at a given tick):

        * ``tls_egress_queues[slot]`` -- Initial-level CRYPTO
          (rustls ServerHello + EncryptedExtensions before the
          KeyChange::Handshake fires).
          Encrypted via flare's :func:`protect_initial_packet`
          (DCID-derived OpenSSL secret per RFC 9001 §5.2).
        * ``tls_handshake_egress_queues[slot]`` -- Handshake-
          level CRYPTO (rustls Certificate + CertificateVerify
          + Finished, between KeyChange::Handshake and
          KeyChange::OneRtt).
          Encrypted via :meth:`_build_handshake_response`
          which routes through rustls's
          ``Keys.local.packet.encrypt_in_place``.
        * ``tls_1rtt_egress_queues[slot]`` -- 1-RTT CRYPTO
          (rustls post-handshake messages like
          NewSessionTicket).
          Encrypted via :meth:`_build_1rtt_handshake_crypto`.
        * ``h3_response_egress`` -- 1-RTT STREAM frames carrying
          H3 response bytes (the live H3 reactor's actual
          payload). Encrypted via
          :meth:`_build_1rtt_h3_stream`.

        Each builder is a no-op (returns empty) when its
        respective queue is empty OR the matching per-level
        readiness sentinel hasn't been installed yet by the
        :meth:`_dispatch_crypto_frames` pump.  Slots whose
        connection is closed (`alive == False`) skip every
        level entirely.

        Errors during build/protect short-circuit to ``False``
        without raising; the silent-drop discipline mirrors the
        inbound side (RFC 9001 §5.2).
        """
        if slot < 0 or slot >= len(self.connections):
            return False
        if slot >= len(self.peer_addrs):
            return False
        if not self.connections[slot].alive:
            return False
        var emitted = False
        var peer = self.peer_addrs[slot]
        # Initial-level (legacy OpenSSL path).
        if (
            slot < len(self.tls_egress_queues)
            and len(self.tls_egress_queues[slot]) > 0
        ):
            var initial_dg = self._build_initial_response(slot)
            if len(initial_dg) > 0:
                _ = self.send_to(Span[UInt8, _](initial_dg), peer)
                self.tls_egress_queues[slot] = List[UInt8]()
                emitted = True
        # Handshake-level (rustls path; gated on the readiness
        # sentinel via _build_handshake_response).
        if (
            slot < len(self.tls_handshake_egress_queues)
            and len(self.tls_handshake_egress_queues[slot]) > 0
        ):
            var hs_dg = self._build_handshake_response(slot)
            if len(hs_dg) > 0:
                _ = self.send_to(Span[UInt8, _](hs_dg), peer)
                self.tls_handshake_egress_queues[slot] = List[UInt8]()
                emitted = True
        # 1-RTT-level CRYPTO (rustls post-handshake; gated on
        # the 1-RTT readiness sentinel).
        if (
            slot < len(self.tls_1rtt_egress_queues)
            and len(self.tls_1rtt_egress_queues[slot]) > 0
        ):
            var rtt_dg = self._build_1rtt_handshake_crypto(slot)
            if len(rtt_dg) > 0:
                _ = self.send_to(Span[UInt8, _](rtt_dg), peer)
                self.tls_1rtt_egress_queues[slot] = List[UInt8]()
                emitted = True
        # H3 response STREAM frames at 1-RTT (the user-visible
        # response path).  Drain each pending (slot, stream_id)
        # entry, wrap in a STREAM frame, encode into a 1-RTT
        # packet via rustls AEAD, send_to.
        if self._drain_h3_response_egress(slot, peer):
            emitted = True
        return emitted

    def _drain_h3_response_egress(
        mut self, slot: Int, peer: SocketAddr
    ) raises -> Bool:
        """Drain every ``(slot, stream_id)`` entry in
        :attr:`h3_response_egress` matching ``slot`` and emit
        one 1-RTT short-header packet per stream.

        Returns True iff at least one packet was sent.

        Each stream's bytes are wrapped in a STREAM frame
        (RFC 9000 §19.8) via :meth:`_build_1rtt_h3_stream`,
        protected at 1-RTT via the slot's rustls session, and
        emitted with ``fin=True`` because the H3 driver's
        ``take_response_frames`` finalizes the response when
        the handler returns (responses are not chunked across
        packets).
        """
        var slot_prefix = String(slot) + ":"
        var emitted = False
        var keys_to_drain = List[String]()
        for entry in self.h3_response_egress.items():
            var k = entry.key
            if k.startswith(slot_prefix):
                keys_to_drain.append(k)
        for i in range(len(keys_to_drain)):
            var k = keys_to_drain[i]
            var bytes = self.h3_response_egress[k].copy()
            if len(bytes) == 0:
                continue
            # Parse the stream_id back out of the key (format
            # is "<slot>:<stream_id>", ascii only, so byte-
            # level iteration is safe).
            var key_bytes = k.as_bytes()
            var sid: UInt64 = UInt64(0)
            var found_colon = False
            var any_digit = False
            for j in range(len(key_bytes)):
                var b = Int(key_bytes[j])
                if not found_colon:
                    if b == 0x3A:  # ':'
                        found_colon = True
                    continue
                if b < 0x30 or b > 0x39:
                    continue
                sid = sid * UInt64(10) + UInt64(b - 0x30)
                any_digit = True
            if not found_colon or not any_digit:
                continue
            var dg = self._build_1rtt_h3_stream(slot, sid, bytes^, fin=True)
            if len(dg) == 0:
                continue
            _ = self.send_to(Span[UInt8, _](dg), peer)
            _ = self.h3_response_egress.pop(k)
            emitted = True
        return emitted

    def _build_initial_response(
        mut self, slot: Int, pn_length: Int = 2
    ) raises -> List[UInt8]:
        """Materialize a server-side Initial packet that carries
        the slot's pending egress CRYPTO bytes.

        Splits cleanly from :meth:`_drain_and_send` so unit tests
        can exercise the wire-format builder without binding a
        UDP socket. Returns the protected datagram bytes ready
        for :meth:`send_to`.

        ``pn_length`` defaults to 2 which is the comfortable
        ServerHello / EncryptedExtensions size for any
        reasonable cert chain (covers 0..65535 packet numbers
        per RFC 9001 §5.3). The caller may raise this to 3 / 4
        once long-running connections cross the 2-byte pn
        window.
        """
        var qbytes = self.tls_egress_queues[slot].copy()
        var conn = self.connections[slot].copy()
        var crypto = CryptoFrame(
            offset=conn.tx_initial_offset, data=qbytes.copy()
        )
        var payload = List[UInt8]()
        encode_crypto(crypto, payload)
        # Build the long-header prefix: server DCID = peer's
        # client-chosen SCID; server SCID = local_cid (same the
        # peer sent in its first Initial's DCID). RFC 9000
        # §17.2.2: the Initial Source Connection ID is the
        # server's chosen CID -- here we echo local_cid so the
        # client's CID->slot routing stays stable.
        var first_bits = (pn_length - 1) & 0x3
        var prefix = encode_long_header(
            PACKET_TYPE_INITIAL,
            QUIC_VERSION_1,
            conn.peer_cid,
            conn.local_cid,
            type_specific_bits=first_bits,
        )
        # Token-length varint (always 0 for server-side Initial
        # responses per RFC 9000 §17.2.2 -- only the client may
        # echo a NEW_TOKEN-issued token).
        var token_len_var = encode_varint(UInt64(0))
        for i in range(len(token_len_var)):
            prefix.append(token_len_var[i])
        # Payload length: CRYPTO frame body + pn_length + 16-byte
        # AEAD tag per RFC 9000 §17.2.5.
        var payload_total = UInt64(len(payload) + pn_length + 16)
        var len_var = encode_varint(payload_total)
        for i in range(len(len_var)):
            prefix.append(len_var[i])
        var pn = conn.tx_initial_pn
        var datagram = protect_initial_packet(
            Span[UInt8, _](prefix),
            packet_number=pn,
            pn_length=pn_length,
            plaintext=Span[UInt8, _](payload),
            dcid=conn.local_cid,
            is_server=True,
        )
        # Advance the connection's outbound Initial-level
        # counters so the next drain emits a fresh pn + offset.
        conn.tx_initial_pn = pn + UInt64(1)
        conn.tx_initial_offset = conn.tx_initial_offset + UInt64(len(qbytes))
        self.connections[slot] = conn^
        return datagram^

    # -- Handshake + 1-RTT egress via rustls --------------------------------

    def _build_handshake_response(
        mut self, slot: Int, pn_length: Int = 2
    ) raises -> List[UInt8]:
        """Wrap the slot's pending Handshake-level CRYPTO bytes
        into a long-header Handshake packet, AEAD-protected via
        the slot's rustls session's
        ``Keys.local.packet.encrypt_in_place`` + header-
        protected via ``Keys.local.header.encrypt_in_place``
        (RFC 9001 §5.3 + §5.4).

        Splits cleanly from :meth:`_drain_and_send` so unit
        tests can exercise the wire-format builder without
        binding a UDP socket.  Returns the protected datagram
        bytes ready for :meth:`send_to`; empty list if the
        slot is out of range, the per-slot Handshake queue is
        empty, or rustls hasn't installed level-2 keys yet
        (the post-handshake-bridge sentinel gate).

        The flow mirrors :meth:`_build_initial_response` but:

        * The header omits the Initial-level token field
          (RFC 9000 §17.2.4 -- Handshake long headers carry
          only the payload-length varint after the SCID).
        * The AEAD + HP routes through
          :func:`_do_packet_encrypt` and
          :func:`_do_header_encrypt` at
          :data:`QuicEncryptionLevel.HANDSHAKE` instead of
          flare's :func:`protect_initial_packet` (the DCID-
          derived OpenSSL Initial path doesn't apply at
          Handshake -- the keys come from rustls's
          ``KeyChange::Handshake`` at the matching session
          slot).
        * The per-connection ``tx_handshake_pn`` +
          ``tx_handshake_offset`` counters advance on success.
        """
        if slot < 0 or slot >= len(self.connections):
            return List[UInt8]()
        if slot >= len(self.tls_handshake_egress_queues):
            return List[UInt8]()
        if len(self.tls_handshake_egress_queues[slot]) == 0:
            return List[UInt8]()
        var conn = self.connections[slot].copy()
        # Per-direction sentinel gates the egress: if rustls
        # hasn't yet emitted KeyChange::Handshake then tx_handshake
        # keys aren't ready.  The pump in `_dispatch_crypto_frames`
        # stamps both rx + tx sentinels together; checking the tx
        # side here keeps the egress aligned with the inbound gate
        # on the same level.
        if len(conn.tx_handshake_secret) == 0:
            return List[UInt8]()
        var handle = self.tls_sessions[slot].handle
        if handle == 0:
            return List[UInt8]()
        if pn_length < 1 or pn_length > 4:
            raise Error(
                "_build_handshake_response: pn_length out of [1, 4]: "
                + String(pn_length)
            )
        # 1. Encode the CRYPTO frame body that wraps the
        # rustls take_crypto output at Handshake level.
        var qbytes = self.tls_handshake_egress_queues[slot].copy()
        var crypto = CryptoFrame(
            offset=conn.tx_handshake_offset, data=qbytes.copy()
        )
        var payload = List[UInt8]()
        encode_crypto(crypto, payload)
        # 2. Build the long-header prefix (no token varint at
        # Handshake level per RFC 9000 §17.2.4).
        var first_bits = (pn_length - 1) & 0x3
        var prefix = encode_long_header(
            PACKET_TYPE_HANDSHAKE,
            QUIC_VERSION_1,
            conn.peer_cid,
            conn.local_cid,
            type_specific_bits=first_bits,
        )
        var payload_total = UInt64(len(payload) + pn_length + 16)
        var len_var = encode_varint(payload_total)
        for i in range(len(len_var)):
            prefix.append(len_var[i])
        # 3. Build the unprotected header = prefix + pn bytes.
        var pn = conn.tx_handshake_pn
        var unprotected_header = List[UInt8]()
        for i in range(len(prefix)):
            unprotected_header.append(prefix[i])
        for i in range(pn_length):
            var shift = (pn_length - 1 - i) * 8
            unprotected_header.append(UInt8((Int(pn) >> shift) & 0xFF))
        # 4. AEAD-encrypt the payload via rustls at level 2.
        # The payload buffer is mutated in place; the returned
        # tag is appended afterward.  The FFI binding helpers
        # take `read lib: OwnedDLHandle`, which borrows without
        # moving, so we pass `self.tls_acceptor._lib` directly
        # at each callsite (the OwnedDLHandle itself is not
        # ImplicitlyCopyable and cannot be aliased into a local).
        var encrypted_payload = payload.copy()
        var tag = _do_packet_encrypt(
            self.tls_acceptor._lib,
            handle,
            QuicEncryptionLevel.HANDSHAKE,
            pn,
            unprotected_header,
            encrypted_payload,
        )
        # 5. Assemble the protected datagram = header + ciphertext + tag.
        var protected = List[UInt8]()
        for i in range(len(unprotected_header)):
            protected.append(unprotected_header[i])
        for i in range(len(encrypted_payload)):
            protected.append(encrypted_payload[i])
        for i in range(len(tag)):
            protected.append(tag[i])
        # 6. Apply header protection via rustls at level 2.
        var pn_offset = len(unprotected_header) - pn_length
        var sample_offset = pn_offset + 4
        if sample_offset + 16 > len(protected):
            raise Error(
                "_build_handshake_response: ciphertext too short for HP sample"
            )
        var sample = List[UInt8]()
        for i in range(16):
            sample.append(protected[sample_offset + i])
        # Stage the first byte + pn bytes on the stack so rustls
        # can XOR them in place; copy back afterward.
        var first_local: UInt8 = protected[0]
        var pn_local = List[UInt8]()
        for i in range(pn_length):
            pn_local.append(protected[pn_offset + i])
        var first_addr = Int(UnsafePointer(to=first_local))
        _do_header_encrypt(
            self.tls_acceptor._lib,
            handle,
            QuicEncryptionLevel.HANDSHAKE,
            sample,
            first_addr,
            Int(pn_local.unsafe_ptr()),
            pn_length,
        )
        protected[0] = first_local
        for i in range(pn_length):
            protected[pn_offset + i] = pn_local[i]
        # 7. Advance the per-connection Handshake counters.
        conn.tx_handshake_pn = pn + UInt64(1)
        conn.tx_handshake_offset = conn.tx_handshake_offset + UInt64(
            len(qbytes)
        )
        self.connections[slot] = conn^
        return protected^

    def _build_1rtt_response(
        mut self,
        slot: Int,
        var plaintext: List[UInt8],
        pn_length: Int = 2,
    ) raises -> List[UInt8]:
        """Wrap an arbitrary 1-RTT plaintext payload (CRYPTO
        bytes from rustls's post-handshake KeyChange::OneRtt
        path, OR STREAM-frame H3 response bytes) into a
        short-header 1-RTT packet, AEAD-protected via the
        slot's rustls session's
        ``Keys.local.packet.encrypt_in_place`` + header-
        protected via ``Keys.local.header.encrypt_in_place``
        at :data:`QuicEncryptionLevel.APPLICATION`.

        ``plaintext`` is the in-place buffer of plaintext
        bytes the caller has already encoded into QUIC frames
        (CRYPTO at level 3 for post-handshake NEW_TOKEN /
        HANDSHAKE_DONE / NEW_CONNECTION_ID, or STREAM for H3).
        The function consumes it.  Returns the protected
        datagram bytes ready for :meth:`send_to`; empty list
        if the slot is out of range, rustls hasn't installed
        1-RTT keys yet, or the session handle is NULL.
        """
        if slot < 0 or slot >= len(self.connections):
            return List[UInt8]()
        var conn = self.connections[slot].copy()
        if len(conn.tx_1rtt_secret) == 0:
            return List[UInt8]()
        if slot >= len(self.tls_sessions):
            return List[UInt8]()
        var handle = self.tls_sessions[slot].handle
        if handle == 0:
            return List[UInt8]()
        if pn_length < 1 or pn_length > 4:
            raise Error(
                "_build_1rtt_response: pn_length out of [1, 4]: "
                + String(pn_length)
            )
        # 1. Build the unprotected short-header prefix.
        # spin_bit + key_phase stay 0 (no key-update yet).
        var prefix = encode_short_header(
            conn.peer_cid,
            spin_bit=False,
            key_phase=False,
            pn_length=pn_length,
        )
        # 2. Build unprotected header = prefix + pn bytes.
        var pn = conn.tx_1rtt_pn
        var unprotected_header = List[UInt8]()
        for i in range(len(prefix)):
            unprotected_header.append(prefix[i])
        for i in range(pn_length):
            var shift = (pn_length - 1 - i) * 8
            unprotected_header.append(UInt8((Int(pn) >> shift) & 0xFF))
        # 3. AEAD-encrypt via rustls at level 3.  See the
        # _build_handshake_response comment for why we pass
        # `self.tls_acceptor._lib` directly at each call.
        var encrypted_payload = plaintext^
        var tag = _do_packet_encrypt(
            self.tls_acceptor._lib,
            handle,
            QuicEncryptionLevel.APPLICATION,
            pn,
            unprotected_header,
            encrypted_payload,
        )
        # 4. Assemble the protected datagram.
        var protected = List[UInt8]()
        for i in range(len(unprotected_header)):
            protected.append(unprotected_header[i])
        for i in range(len(encrypted_payload)):
            protected.append(encrypted_payload[i])
        for i in range(len(tag)):
            protected.append(tag[i])
        # 5. Apply header protection via rustls at level 3.
        var pn_offset = len(unprotected_header) - pn_length
        var sample_offset = pn_offset + 4
        if sample_offset + 16 > len(protected):
            raise Error(
                "_build_1rtt_response: ciphertext too short for HP sample"
            )
        var sample = List[UInt8]()
        for i in range(16):
            sample.append(protected[sample_offset + i])
        var first_local: UInt8 = protected[0]
        var pn_local = List[UInt8]()
        for i in range(pn_length):
            pn_local.append(protected[pn_offset + i])
        var first_addr = Int(UnsafePointer(to=first_local))
        _do_header_encrypt(
            self.tls_acceptor._lib,
            handle,
            QuicEncryptionLevel.APPLICATION,
            sample,
            first_addr,
            Int(pn_local.unsafe_ptr()),
            pn_length,
        )
        protected[0] = first_local
        for i in range(pn_length):
            protected[pn_offset + i] = pn_local[i]
        # 6. Advance the 1-RTT pn counter (no offset counter at
        # 1-RTT -- per-stream offsets live on each STREAM frame
        # encoded into the plaintext).
        conn.tx_1rtt_pn = pn + UInt64(1)
        self.connections[slot] = conn^
        return protected^

    def _build_1rtt_handshake_crypto(
        mut self, slot: Int, pn_length: Int = 2
    ) raises -> List[UInt8]:
        """Wrap the slot's pending 1-RTT-level CRYPTO bytes
        (rustls post-handshake messages: NewSessionTicket etc.)
        into a 1-RTT packet via :meth:`_build_1rtt_response`.

        Distinct from H3 STREAM-frame egress which lives under
        :meth:`_build_1rtt_h3_stream`; both end up calling
        :meth:`_build_1rtt_response` with the appropriate
        plaintext.
        """
        if slot >= len(self.tls_1rtt_egress_queues):
            return List[UInt8]()
        if len(self.tls_1rtt_egress_queues[slot]) == 0:
            return List[UInt8]()
        if slot < 0 or slot >= len(self.connections):
            return List[UInt8]()
        # Wrap the bytes in a CRYPTO frame -- the offset is
        # tracked per-stream-id at the 1-RTT level, but for the
        # CRYPTO frame stream the offset is just a monotonic
        # counter.  rustls's post-handshake messages are small
        # and infrequent so a fresh CryptoFrame(offset=0) per
        # drain is correct as long as the egress queue gets
        # cleared every flush (which it does in `_drain_and_send`).
        var qbytes = self.tls_1rtt_egress_queues[slot].copy()
        var crypto = CryptoFrame(offset=UInt64(0), data=qbytes^)
        var plaintext = List[UInt8]()
        encode_crypto(crypto, plaintext)
        return self._build_1rtt_response(slot, plaintext^, pn_length)

    def _build_1rtt_h3_stream(
        mut self,
        slot: Int,
        stream_id: UInt64,
        var stream_bytes: List[UInt8],
        fin: Bool,
        pn_length: Int = 2,
    ) raises -> List[UInt8]:
        """Wrap a STREAM frame carrying ``stream_bytes`` for
        the given QUIC stream id into a 1-RTT short-header
        packet.

        H3 response bytes (HEADERS + DATA frames already
        encoded by the H3 driver) get framed here into the
        QUIC STREAM frame shape per RFC 9000 §19.8 + RFC 9000
        §17.3.1 short-header encryption.

        ``fin`` flips the STREAM frame's FIN bit; the H3
        driver sets True when the response is complete.
        ``stream_id`` is the QUIC stream id, monotonically
        increasing per RFC 9000 §2.1 numbering rules.
        """
        if len(stream_bytes) == 0 and not fin:
            return List[UInt8]()
        # Encode the STREAM frame body inline.  Frame type
        # bits per RFC 9000 §19.8:
        #
        #   0b00001 | OFF | LEN | FIN
        #
        # We always set OFF (we encode an offset) + LEN (we
        # encode a length) so the frame is self-describing for
        # interleaved STREAMs; FIN per the caller's flag.
        var frame_type: Int = 0x08 | 0x04 | 0x02
        if fin:
            frame_type |= 0x01
        var plaintext = List[UInt8]()
        plaintext.append(UInt8(frame_type))
        var sid_var = encode_varint(stream_id)
        for i in range(len(sid_var)):
            plaintext.append(sid_var[i])
        var off_var = encode_varint(UInt64(0))
        for i in range(len(off_var)):
            plaintext.append(off_var[i])
        var len_var = encode_varint(UInt64(len(stream_bytes)))
        for i in range(len(len_var)):
            plaintext.append(len_var[i])
        for i in range(len(stream_bytes)):
            plaintext.append(stream_bytes[i])
        return self._build_1rtt_response(slot, plaintext^, pn_length)

    def run(mut self) raises:
        """Run the listener's event loop. Blocks until
        :meth:`shutdown` flips the stop flag.

        The loop drives the full I/O cycle
        ``recv -> dispatch -> drain -> protect -> sendto ->
        advance_timers``:

        1. ``tick(100)`` blocks up to 100 ms in ``recv_from``;
           on a datagram it runs the dispatch + handle + drain
           chain.
        2. On a 100 ms timeout it still calls
           :meth:`drain_all_egress` so any session that started
           handshaking can flush its first response.
        3. :meth:`advance_timers` then runs the wheel against
           the current monotonic clock so PTO + idle + ack-delay
           callbacks fire on time.

        The 100 ms recv timeout caps the worst-case timer slop
        and the shutdown-flag polling interval.
        """
        while not self._stopping:
            _ = self.tick(timeout_ms=100)
            var now_ms = _monotonic_ms()
            _ = self.advance_timers(now_ms)

    def shutdown(mut self):
        """Request the event loop to exit. Idempotent; safe to
        call from a signal handler (sets a single Bool flag)."""
        self._stopping = True

    # -- Timer scheduling -----------------------------------------------

    def schedule_idle_timeout(mut self, slot: Int) raises -> UInt64:
        """Arm the idle timer for ``slot`` at
        ``config.max_idle_timeout_ms`` from the current wheel
        tick. Cancels the slot's previous idle timer if any so
        every ``handle_packet`` only ever has one idle timer in
        flight per connection.

        Returns the new timer id (stored back into the slot's
        :attr:`QuicConnection.idle_timer_id`).
        """
        if slot < 0 or slot >= len(self.connections):
            raise Error(
                "schedule_idle_timeout: slot " + String(slot) + " out of range"
            )
        var conn = self.connections[slot].copy()
        if conn.idle_timer_id != UInt64(0):
            _ = self.timer_wheel.cancel(conn.idle_timer_id)
            conn.idle_timer_id = UInt64(0)
        var token = encode_timer_token(TIMER_KIND_IDLE, slot)
        var after_ms = Int(self.config.max_idle_timeout_ms)
        var id = self.timer_wheel.schedule(after_ms=after_ms, token=token)
        conn.idle_timer_id = id
        self.connections[slot] = conn^
        return id

    def schedule_pto(mut self, slot: Int, after_ms: Int) raises -> UInt64:
        """Arm the PTO probe-timer for ``slot``. Cancels any
        existing PTO entry first so re-arming on every send
        doesn't pile up wheel entries."""
        if slot < 0 or slot >= len(self.connections):
            raise Error("schedule_pto: slot " + String(slot) + " out of range")
        var conn = self.connections[slot].copy()
        if conn.pto_timer_id != UInt64(0):
            _ = self.timer_wheel.cancel(conn.pto_timer_id)
            conn.pto_timer_id = UInt64(0)
        var token = encode_timer_token(TIMER_KIND_PTO, slot)
        var id = self.timer_wheel.schedule(after_ms=after_ms, token=token)
        conn.pto_timer_id = id
        self.connections[slot] = conn^
        return id

    def schedule_ack_delay(mut self, slot: Int, after_ms: Int) raises -> UInt64:
        """Arm the deferred-ACK timer for ``slot``. Idempotent
        no-op if a deferred-ACK timer is already scheduled --
        an in-flight deferred ACK should not be re-armed each
        time another ack-eliciting packet arrives (the existing
        timer already covers the deadline)."""
        if slot < 0 or slot >= len(self.connections):
            raise Error(
                "schedule_ack_delay: slot " + String(slot) + " out of range"
            )
        var conn = self.connections[slot].copy()
        if conn.ack_delay_timer_id != UInt64(0):
            return conn.ack_delay_timer_id
        var token = encode_timer_token(TIMER_KIND_ACK_DELAY, slot)
        var id = self.timer_wheel.schedule(after_ms=after_ms, token=token)
        conn.ack_delay_timer_id = id
        self.connections[slot] = conn^
        return id

    def advance_timers(mut self, now_ms: UInt64) raises -> Int:
        """Advance the wheel to ``now_ms`` and dispatch every
        fired token to the matching :class:`QuicConnection`
        callback (PTO / IDLE / ACK_DELAY per
        :mod:`flare.quic.timers`). Returns the number of tokens
        dispatched.

        Also sweeps the CID table for any connections whose
        ``alive`` flag flipped False during dispatch (idle
        timeout, draining); their CIDs are retired so a stray
        retransmit doesn't route to a dead slot.
        """
        var fired = List[UInt64]()
        self.timer_wheel.advance(now_ms, fired)
        for i in range(len(fired)):
            var decoded = decode_timer_token(fired[i])
            var slot = decoded.slot
            if slot < 0 or slot >= len(self.connections):
                continue
            var conn = self.connections[slot].copy()
            if decoded.kind == TIMER_KIND_IDLE:
                conn.on_idle_expired()
            elif decoded.kind == TIMER_KIND_PTO:
                conn.on_pto_expired()
            elif decoded.kind == TIMER_KIND_ACK_DELAY:
                conn.on_ack_delay_expired()
            self.connections[slot] = conn^
            if not self.connections[slot].alive:
                self._retire_slot_cids(slot)
        return len(fired)

    def _retire_slot_cids(mut self, slot: Int) raises:
        """Drop every CID -> slot mapping that points at this
        slot. Called when the slot's connection has closed so
        late retransmits don't route to a dead slot."""
        if slot < 0 or slot >= len(self.connections):
            return
        var cid_hex = cid_to_hex(self.connections[slot].local_cid)
        self.cid_table.retire(cid_hex)

    def close(mut self):
        """Close the underlying UDP socket. Idempotent. The
        :class:`UdpSocket` destructor also closes the fd, so
        explicit calls are only required when callers want to
        free the port before the listener goes out of scope."""
        self._socket.close()
