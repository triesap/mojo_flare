"""Tests for the WebSocket permessage-deflate extension (RFC 7692).

Eight cases per the v0.7 deferred plan:

1. Client offer round-trips through ``parse_extensions``.
2. Parameter parser handles flags + ``key=value`` + quoted values.
3. Server negotiation picks the first ``permessage-deflate`` offer
   and forces ``no_context_takeover`` on both sides (v0.7 codec
   constraint).
4. Server negotiation returns ``None`` when no offer matches.
5. ``compress_message`` -> ``decompress_message`` round-trips a
   non-trivial UTF-8 payload.
6. Compress on an empty payload + decompress reject of empty
   compressed payload (RFC 7692 §7.2.3.6).
7. Decompress respects ``max_decompressed_bytes`` (zip-bomb
   guard) and raises a clear error.
8. RSV1 handshake honesty: the offer header reflects which
   ``no_context_takeover`` flags are on; cfg parameters survive
   round-trip through parse + negotiate.
"""

from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.ws.extensions import (
    build_permessage_deflate_offer,
    negotiate_permessage_deflate,
    parse_extensions,
)
from flare.ws.permessage_deflate import (
    DEFAULT_DEFLATE_LEVEL,
    DEFAULT_MAX_DECOMPRESSED_BYTES,
    PermessageDeflateConfig,
    compress_message,
    decompress_message,
)


def test_parse_simple_offer_round_trips() raises:
    """A simple ``permessage-deflate`` offer with two flags + one
    value parameter parses into the expected shape."""
    var offers = parse_extensions(
        "permessage-deflate; client_no_context_takeover;"
        " server_max_window_bits=12"
    )
    assert_equal(len(offers), 1)
    var o = offers[0].copy()
    assert_equal(o.name, "permessage-deflate")
    assert_true(o.has("client_no_context_takeover"))
    var smw = o.get("server_max_window_bits")
    assert_true(Bool(smw))
    assert_equal(smw.value(), "12")
    var sct = o.get("client_no_context_takeover")
    assert_true(Bool(sct))
    assert_equal(sct.value(), "")


def test_parse_handles_flags_kv_quoted_values_multi_offer() raises:
    """Multiple comma-delimited offers + a quoted-string value
    parse correctly; case is folded on extension + parameter
    names; whitespace is tolerated."""
    var offers = parse_extensions(
        'Permessage-Deflate ; client_max_window_bits , x-custom; q="0.7" '
    )
    assert_equal(len(offers), 2)
    assert_equal(offers[0].name, "permessage-deflate")
    var cmw = offers[0].get("client_max_window_bits")
    assert_true(Bool(cmw))
    assert_equal(cmw.value(), "")
    assert_equal(offers[1].name, "x-custom")
    var qval = offers[1].get("q")
    assert_true(Bool(qval))
    assert_equal(qval.value(), "0.7")


def test_negotiate_picks_first_pmd_offer_and_locks_no_context_takeover() raises:
    """The server picks the first ``permessage-deflate`` offer and
    the response value reflects the v0.7 codec invariant
    (``no_context_takeover`` on both sides)."""
    var offers = parse_extensions(
        "x-bogus; foo=bar, permessage-deflate; client_max_window_bits"
    )
    var cfg = PermessageDeflateConfig()
    cfg.enabled = True
    var got = negotiate_permessage_deflate(offers, cfg)
    assert_true(Bool(got))
    var t = got.value().copy()
    var hdr = t[0]
    var negotiated = t[1].copy()
    assert_true(hdr.find("permessage-deflate") >= 0)
    assert_true(hdr.find("client_no_context_takeover") >= 0)
    assert_true(hdr.find("server_no_context_takeover") >= 0)
    assert_true(negotiated.client_no_context_takeover)
    assert_true(negotiated.server_no_context_takeover)


def test_negotiate_returns_none_when_no_offer_matches() raises:
    """No ``permessage-deflate`` offer + the server returns
    ``None`` (the upgrade response simply omits the
    ``Sec-WebSocket-Extensions`` header)."""
    var offers = parse_extensions("x-bogus; foo=bar")
    var cfg = PermessageDeflateConfig()
    cfg.enabled = True
    var got = negotiate_permessage_deflate(offers, cfg)
    assert_false(Bool(got))


def test_compress_decompress_round_trip_utf8_payload() raises:
    """A non-trivial UTF-8 payload survives compress -> decompress
    byte-for-byte."""
    var msg = String(
        "the quick brown fox jumps over the lazy dog "
        "0123456789 the quick brown fox jumps over the lazy dog"
    )
    var compressed = compress_message(
        Span[UInt8, _](msg.as_bytes()), DEFAULT_DEFLATE_LEVEL
    )
    assert_true(len(compressed) > 0)
    # The compressed form should be smaller than the input on a
    # repetitive payload like this.
    assert_true(len(compressed) < msg.byte_length())
    var decompressed = decompress_message(
        Span[UInt8, _](compressed), DEFAULT_MAX_DECOMPRESSED_BYTES
    )
    assert_equal(len(decompressed), msg.byte_length())
    var orig = msg.as_bytes()
    for i in range(len(decompressed)):
        assert_equal(Int(decompressed[i]), Int(orig[i]))


def test_compress_empty_payload_emits_single_byte_and_decompress_rejects() raises:
    """Empty plaintext -> one-byte compressed output (RFC 7692
    §7.2.3.6); empty *compressed* input is rejected."""
    var empty = List[UInt8]()
    var compressed = compress_message(Span[UInt8, _](empty))
    assert_equal(len(compressed), 1)
    assert_equal(Int(compressed[0]), 0x00)
    with assert_raises(contains="empty payload"):
        _ = decompress_message(Span[UInt8, _](empty))


def test_decompress_respects_max_decompressed_bytes_cap() raises:
    """A high-ratio payload that would inflate past the cap raises
    rather than silently producing many MiB of output."""
    # Build a 256 KiB plaintext of a single repeated byte; this
    # compresses to a few hundred bytes, then decompresses back to
    # 256 KiB. With a 16 KiB cap the decompressor must raise.
    var big = List[UInt8]()
    for _ in range(256 * 1024):
        big.append(UInt8(0x41))
    var compressed = compress_message(Span[UInt8, _](big))
    with assert_raises(contains="max_decompressed_bytes"):
        _ = decompress_message(Span[UInt8, _](compressed), 16 * 1024)


def test_offer_emit_reflects_config_flags() raises:
    """The offer-builder honors the cfg flags so a server reading
    the response can trust that the codec mode is what the
    handshake claims."""
    var cfg = PermessageDeflateConfig()
    cfg.enabled = True
    cfg.client_no_context_takeover = True
    cfg.server_no_context_takeover = False
    cfg.client_max_window_bits = 12
    var hdr = build_permessage_deflate_offer(cfg)
    assert_true(hdr.find("permessage-deflate") >= 0)
    assert_true(hdr.find("client_no_context_takeover") >= 0)
    assert_false(hdr.find("server_no_context_takeover") >= 0)
    assert_true(hdr.find("client_max_window_bits=12") >= 0)
    # Disabled cfg -> empty header (we offer nothing).
    var off = PermessageDeflateConfig()
    assert_equal(build_permessage_deflate_offer(off), "")


def main() raises:
    test_parse_simple_offer_round_trips()
    test_parse_handles_flags_kv_quoted_values_multi_offer()
    test_negotiate_picks_first_pmd_offer_and_locks_no_context_takeover()
    test_negotiate_returns_none_when_no_offer_matches()
    test_compress_decompress_round_trip_utf8_payload()
    test_compress_empty_payload_emits_single_byte_and_decompress_rejects()
    test_decompress_respects_max_decompressed_bytes_cap()
    test_offer_emit_reflects_config_flags()
    print("test_ws_permessage_deflate: 8 passed")
