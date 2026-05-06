"""WebSocket permessage-deflate extension (RFC 7692).

Per-message DEFLATE compression for WebSocket data frames. The
extension is negotiated via ``Sec-WebSocket-Extensions`` during
the opening handshake (see :mod:`flare.ws.extensions`); after a
successful negotiation the peers compress every TEXT/BINARY data
frame individually -- the RSV1 bit signals that the payload is
DEFLATE-encoded (RFC 7692 §6).

Wire shape (RFC 7692 §7.2):

- The compressed payload is a *raw* DEFLATE stream (no zlib or
  gzip header) terminated with a sync flush.
- The encoder MUST drop the trailing 4 bytes ``0x00 0x00 0xff 0xff``
  before placing the bytes on the wire (the spec calls this
  "removing the empty deflate block").
- The decoder MUST append the same 4 bytes back to the payload
  before passing it to ``inflate``.

v0.7 implementation choices (per the deferred-list coverage
acknowledgment):

- Both directions run with ``no_context_takeover`` enforced --
  every message is compressed against a fresh sliding window so
  there is no streaming z_stream state to manage across calls.
  RFC 7692 §7.1.1 calls this the safest mode and explicitly
  permits implementations to require it.
- ``max_window_bits`` is fixed at 15 (the default); any
  smaller-window offer is silently negotiated up to 15.
- A per-message decompressed-size cap (default 16 MiB) is
  enforced before any allocation -- this is the same defense
  the rest of flare uses against zip-bomb / compression-oracle
  payloads.
- The compressor uses :data:`DEFAULT_DEFLATE_LEVEL` = 6 (zlib's
  default); callers may override per-direction via
  :class:`PermessageDeflateConfig`.

Public surface:

- :class:`PermessageDeflateConfig` -- per-side knobs.
- :func:`compress_message(plaintext, level)` -> ``List[UInt8]``.
- :func:`decompress_message(compressed, max_decompressed_bytes)`
  -> ``List[UInt8]``; raises if the cap is exceeded.

Higher-level frame integration (RSV1 dispatch on send/recv) lives
in :mod:`flare.ws.client_h2` for the h2 path and as a flag on
:class:`flare.ws.frame.WsFrame.rsv1` for the h1 path -- the codec
side is fully isolated here so the compression-oracle hardening
review only needs to scrutinise this single file.
"""

from std.ffi import OwnedDLHandle, c_int

from ..http.encoding import _find_flare_zlib_lib


comptime DEFAULT_DEFLATE_LEVEL: Int = 6
"""zlib's default compression level (1..9, where 9 is slowest /
densest). Used when :class:`PermessageDeflateConfig` doesn't
override per-direction."""

comptime DEFAULT_MAX_DECOMPRESSED_BYTES: Int = 16 * 1024 * 1024
"""Per-message decompressed-size cap (16 MiB). The decoder bails
with an Error before allocating output past this size; callers
should treat the failure as a protocol violation and close the
connection with :data:`WsCloseCode.MESSAGE_TOO_BIG` (1009).
This is the simplest defense against zip-bomb / compression-oracle
payloads -- attackers who can pick the plaintext can otherwise
inflate a few-byte ciphertext into many MiB of decompressed
output, exhausting the server."""

comptime _SYNC_FLUSH_TRAILER: List[UInt8] = List[UInt8](
    UInt8(0x00), UInt8(0x00), UInt8(0xFF), UInt8(0xFF)
)
"""RFC 7692 §7.2.1: the empty-deflate-block trailer the encoder
removes and the decoder appends back."""


struct PermessageDeflateConfig(Copyable, Defaultable, Movable):
    """Per-side knobs for the permessage-deflate extension.

    All four RFC 7692 §7.1 parameters are surfaced for negotiation
    + symmetry, even though the v0.7 codec implementation always
    runs with ``no_context_takeover`` on both sides (see module
    docstring). ``max_window_bits`` <= 15 is accepted; the codec
    never produces output that violates the cap because raw
    deflate with windowBits = -15 already keeps the window at
    most 32 KiB.
    """

    var enabled: Bool
    """Master switch. ``False`` (the default) means the extension
    is neither offered (client) nor accepted (server) during the
    handshake."""

    var server_no_context_takeover: Bool
    """Whether the server MUST reset its LZ77 context at the end
    of each message. v0.7 always enforces ``True`` regardless of
    this value -- surfaced for handshake honesty."""

    var client_no_context_takeover: Bool
    """Whether the client MUST reset its LZ77 context at the end
    of each message. v0.7 always enforces ``True`` regardless of
    this value -- surfaced for handshake honesty."""

    var server_max_window_bits: Int
    """Max bits in the LZ77 sliding window the server is willing
    to use. Range 8..15; v0.7 always operates at 15."""

    var client_max_window_bits: Int
    """Same as :attr:`server_max_window_bits` for the client
    side."""

    var compression_level: Int
    """zlib compression level for outgoing messages (1..9, 0 =
    no compression, -1 = zlib default). Defaults to
    :data:`DEFAULT_DEFLATE_LEVEL`."""

    var max_decompressed_bytes: Int
    """Per-message decompressed-size cap (bytes). Defaults to
    :data:`DEFAULT_MAX_DECOMPRESSED_BYTES` (16 MiB). Set to a
    smaller value on memory-constrained servers; do **not** raise
    above 64 MiB without first auditing the rest of the
    request-pipeline for unbounded buffering."""

    def __init__(out self):
        self.enabled = False
        self.server_no_context_takeover = True
        self.client_no_context_takeover = True
        self.server_max_window_bits = 15
        self.client_max_window_bits = 15
        self.compression_level = DEFAULT_DEFLATE_LEVEL
        self.max_decompressed_bytes = DEFAULT_MAX_DECOMPRESSED_BYTES


# ── Compression (raw DEFLATE + strip sync trailer) ───────────────


def _do_compress_raw_deflate(
    read lib: OwnedDLHandle,
    data: Span[UInt8, _],
    level: c_int,
) raises -> List[UInt8]:
    """Compress ``data`` as a raw DEFLATE stream via
    ``flare_compress_raw_deflate``.

    The wrapper always emits ``Z_SYNC_FLUSH`` so the output ends
    with the empty-deflate-block trailer ``0x00 0x00 0xff 0xff``.
    Callers are responsible for stripping those 4 bytes before
    placing the result on the wire (RFC 7692 §7.2.1).

    Args:
        lib: Borrowed handle to ``libflare_zlib.so`` (kept mapped
            across the FFI call).
        data: Plaintext input.
        level: zlib compression level passed through to
            ``deflateInit2``.
    """
    var fn_compress = lib.get_function[
        def(Int, c_int, Int, c_int, c_int) thin abi("C") -> c_int
    ]("flare_compress_raw_deflate")

    # zlib's worst-case bound: srclen + (srclen >> 12) + (srclen >> 14)
    # + (srclen >> 25) + 13. We add a constant slack for the empty
    # block trailer and short inputs.
    var n = len(data)
    var cap = n + (n >> 11) + 16 + 64
    while True:
        var out = List[UInt8](capacity=cap)
        out.resize(cap, 0)
        var written = fn_compress(
            Int(data.unsafe_ptr()),
            c_int(n),
            Int(out.unsafe_ptr()),
            c_int(cap),
            level,
        )
        if Int(written) < 0:
            raise Error("flare_compress_raw_deflate failed: " + String(written))
        if Int(written) < cap:
            out.resize(Int(written), 0)
            return out^
        cap *= 2


def compress_message(
    data: Span[UInt8, _], level: Int = DEFAULT_DEFLATE_LEVEL
) raises -> List[UInt8]:
    """Compress one WebSocket message per RFC 7692 §7.2.1.

    Returns the raw-DEFLATE-encoded bytes with the trailing
    ``0x00 0x00 0xff 0xff`` sync marker stripped. The caller
    places the result in a WS data frame with the RSV1 bit set
    (RFC 7692 §6).

    Args:
        data: Plaintext message bytes.
        level: zlib compression level (1..9; 0 = no compression;
            -1 = zlib default).

    Returns:
        The compressed payload, ready for the wire.

    Raises:
        Error: If the underlying zlib call reports an error.
    """
    if len(data) == 0:
        # RFC 7692 §7.2.3.6: an empty payload compresses to a single
        # 0x00 byte; the strip-trailer rule still applies. Emit
        # exactly one zero byte to match Chrome / Firefox behaviour.
        var out = List[UInt8]()
        out.append(UInt8(0x00))
        return out^
    var lib = OwnedDLHandle(_find_flare_zlib_lib())
    var raw = _do_compress_raw_deflate(lib, data, c_int(level))
    # Strip the trailing 4-byte sync marker. RFC 7692 §7.2.1: the
    # encoder MUST remove the empty deflate block. If the trailer
    # isn't present (zlib emitted Z_FINISH before flush) we leave
    # the bytes untouched -- the decoder side will append the
    # marker unconditionally and inflate will tolerate the trailing
    # 0x00 0x00 0xff 0xff sync block.
    var n = len(raw)
    if (
        n >= 4
        and raw[n - 4] == UInt8(0x00)
        and raw[n - 3] == UInt8(0x00)
        and raw[n - 2] == UInt8(0xFF)
        and raw[n - 1] == UInt8(0xFF)
    ):
        var trimmed = List[UInt8](capacity=n - 4)
        for i in range(n - 4):
            trimmed.append(raw[i])
        return trimmed^
    return raw^


# ── Decompression (re-append sync trailer + raw INFLATE + cap) ───


def _do_decompress_raw_inflate_capped(
    read lib: OwnedDLHandle,
    data: Span[UInt8, _],
    max_out: Int,
) raises -> List[UInt8]:
    """Decompress raw DEFLATE input, growing the output buffer up
    to ``max_out`` bytes; raise if the decoder would exceed the
    cap.

    Uses ``flare_decompress`` with ``windowBits = -15`` (raw
    inflate). ``max_out`` is the per-message decompressed-size
    cap from :class:`PermessageDeflateConfig`.

    Args:
        lib: Borrowed handle to ``libflare_zlib.so``.
        data: The compressed payload (with the sync trailer
            already re-appended).
        max_out: The decompressed-size cap.
    """
    var fn_decomp = lib.get_function[
        def(Int, c_int, Int, c_int, c_int) thin abi("C") -> c_int
    ]("flare_decompress")
    var window_bits = c_int(-15)
    var cap = max(len(data) * 4, 4096)
    if cap > max_out:
        cap = max_out
    while True:
        var out = List[UInt8](capacity=cap)
        out.resize(cap, 0)
        var written = fn_decomp(
            Int(data.unsafe_ptr()),
            c_int(len(data)),
            Int(out.unsafe_ptr()),
            c_int(cap),
            window_bits,
        )
        if Int(written) < 0:
            raise Error("flare_decompress failed: " + String(written))
        if Int(written) < cap:
            out.resize(Int(written), 0)
            return out^
        # Output buffer was completely filled -- might be truncated.
        # Try doubling, but never above ``max_out`` (RFC 7692
        # zip-bomb cap).
        if cap >= max_out:
            raise Error(
                "permessage-deflate: decompressed output exceeded"
                " max_decompressed_bytes ("
                + String(max_out)
                + " bytes)"
            )
        cap *= 2
        if cap > max_out:
            cap = max_out


def decompress_message(
    data: Span[UInt8, _],
    max_decompressed_bytes: Int = DEFAULT_MAX_DECOMPRESSED_BYTES,
) raises -> List[UInt8]:
    """Decompress one WebSocket message per RFC 7692 §7.2.2.

    Re-appends the ``0x00 0x00 0xff 0xff`` sync marker the encoder
    stripped, then runs raw DEFLATE inflate. The decompressed
    output is capped at ``max_decompressed_bytes`` to defuse
    zip-bomb / compression-oracle payloads -- exceeding the cap
    raises an Error and the caller MUST close the connection
    with status code 1009 (MESSAGE_TOO_BIG).

    Args:
        data: The on-wire compressed payload (sync marker stripped).
        max_decompressed_bytes: The per-message size cap. Defaults
            to :data:`DEFAULT_MAX_DECOMPRESSED_BYTES` (16 MiB).

    Returns:
        The plaintext message bytes.

    Raises:
        Error: If the cap is exceeded or zlib reports a
            non-recoverable error.
    """
    if len(data) == 0:
        raise Error(
            "permessage-deflate: empty payload (RFC 7692 §7.2.2 forbids"
            " a zero-length compressed message)"
        )
    var n = len(data)
    var with_trailer = List[UInt8](capacity=n + 4)
    for i in range(n):
        with_trailer.append(data[i])
    with_trailer.append(UInt8(0x00))
    with_trailer.append(UInt8(0x00))
    with_trailer.append(UInt8(0xFF))
    with_trailer.append(UInt8(0xFF))
    var lib = OwnedDLHandle(_find_flare_zlib_lib())
    return _do_decompress_raw_inflate_capped(
        lib, Span[UInt8, _](with_trailer), max_decompressed_bytes
    )
