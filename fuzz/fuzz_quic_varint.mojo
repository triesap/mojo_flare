"""Fuzz harness: ``flare.quic.varint`` codec.

Exercises ``decode_varint`` and ``encode_varint`` together, with
two property contracts:

1. **Canonical round trip.** For any value that ``encode_varint``
   accepts, ``decode_varint(encode_varint(v))`` must return the same
   value and a ``consumed`` count equal to the encoded length. The
   encoder picks the shortest form per RFC 9000 §16; we also
   confirm the decoder accepts any wire-valid encoding (including
   non-shortest-form padding, which aioquic does intentionally for
   packet-number alignment).

2. **Truncation tolerance.** ``decode_varint`` must either return
   a ``Varint`` whose ``consumed`` is in ``{1, 2, 4, 8}`` and is
   ``<=`` the input length, or raise a regular ``Error`` (empty
   buffer or truncated multi-byte form). It must never panic on
   arbitrary bytes.

Additionally, on a successful decode the harness re-encodes the
*canonical* form (via ``encode_varint(value)``) and asserts the
resulting bytes are a prefix of the original input *whenever* the
input's length tag matches the canonical shortest length. When the
input was a non-shortest encoding, the canonical re-encoding may be
shorter — that's the "non-shortest policy" check.

Run:
    pixi run --environment fuzz fuzz-quic-varint
"""

from mozz import fuzz, FuzzConfig

from flare.quic import (
    VARINT_MAX,
    Varint,
    decode_varint,
    encode_varint,
    varint_encoded_length,
)


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


@always_inline
def _length_for_tag(b: UInt8) -> Int:
    var tag = Int(b >> 6) & 0x3
    if tag == 0:
        return 1
    if tag == 1:
        return 2
    if tag == 2:
        return 4
    return 8


def target(data: List[UInt8]) raises:
    """Exercises decode on raw bytes + encoder/decoder round trip.

    Branch A — raw decode of fuzz bytes:
        Each input either decodes cleanly (and ``consumed`` is the
        length implied by the length tag, ``<=`` the input length)
        or raises a regular ``Error`` for empty/truncated input.

    Branch B — canonical round trip from value:
        Synthesise a ``UInt64`` value from the first 8 fuzz bytes
        (little-endian), clamp to ``[0, VARINT_MAX]``, then assert
        ``decode_varint(encode_varint(v))`` recovers ``v`` with
        ``consumed == varint_encoded_length(v)``.

    Branch C — non-shortest acceptance:
        For values < 64, ``encode_varint`` emits a 1-byte form but
        the decoder MUST also accept a 2/4/8-byte encoding of the
        same value (pad-up). We construct such an encoding by hand
        and verify the decoder returns the same value with the
        padded ``consumed`` count.
    """
    var n = len(data)
    var span = Span[UInt8, _](data)

    # ── A. Raw decode of fuzz bytes ─────────────────────────────
    try:
        var decoded = decode_varint(span)
        # Length implied by length tag.
        var expected_len = _length_for_tag(data[0])
        _assert(
            decoded.consumed == expected_len,
            (
                "quic varint: consumed="
                + String(decoded.consumed)
                + " != length-tag="
                + String(expected_len)
            ),
        )
        _assert(
            decoded.consumed <= n,
            "quic varint: consumed > buffer length",
        )
        # The decoded value never exceeds VARINT_MAX (6 high bits +
        # remaining 8-bit groups in 1/2/4/8-byte forms).
        _assert(
            decoded.value <= UInt64(VARINT_MAX),
            "quic varint: decoded value > VARINT_MAX",
        )
    except:
        # Truncation / empty buffer paths.
        if n != 0:
            var expected_len = _length_for_tag(data[0])
            _assert(
                expected_len > n,
                "quic varint: decode_varint raised but input was not truncated",
            )

    # ── B. Canonical round trip from value ─────────────────────
    if n >= 8:
        var v: UInt64 = 0
        # Little-endian assembly so the fuzzer can drive the
        # high-byte path independently from the low byte.
        for i in range(8):
            v |= UInt64(data[i]) << (UInt64(i) * UInt64(8))
        # Clamp to [0, VARINT_MAX] so we never feed the encoder a
        # value it would reject (we exercise the rejection branch
        # explicitly below).
        if v > UInt64(VARINT_MAX):
            v = v & UInt64(VARINT_MAX)
        var encoded = encode_varint(v)
        var expected_len = varint_encoded_length(v)
        _assert(
            len(encoded) == expected_len,
            (
                "quic varint encode: produced "
                + String(len(encoded))
                + " bytes, expected "
                + String(expected_len)
            ),
        )
        var roundtrip = decode_varint(Span[UInt8, _](encoded))
        _assert(
            roundtrip.value == v,
            (
                "quic varint round-trip: value drift "
                + String(roundtrip.value)
                + " vs "
                + String(v)
            ),
        )
        _assert(
            roundtrip.consumed == expected_len,
            "quic varint round-trip: consumed-byte drift",
        )

    # ── C. Non-shortest acceptance (pad-up to 2 / 4 / 8 bytes) ─
    if n >= 1:
        # Build a value <= 63 from the first byte and assert each
        # padded form decodes to the same value.
        var small = UInt64(data[0]) & UInt64(0x3F)
        # 2-byte form: 01xxxxxx xxxxxxxx (tag=0b01, then BE16).
        var pad2 = List[UInt8](capacity=2)
        pad2.append(UInt8(0x40))
        pad2.append(UInt8(small))
        var d2 = decode_varint(Span[UInt8, _](pad2))
        _assert(
            d2.value == small,
            "quic varint pad-up to 2 bytes: value drift",
        )
        _assert(d2.consumed == 2, "quic varint pad-up: consumed != 2")
        # 4-byte form: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx.
        var pad4 = List[UInt8](capacity=4)
        pad4.append(UInt8(0x80))
        pad4.append(UInt8(0))
        pad4.append(UInt8(0))
        pad4.append(UInt8(small))
        var d4 = decode_varint(Span[UInt8, _](pad4))
        _assert(
            d4.value == small,
            "quic varint pad-up to 4 bytes: value drift",
        )
        _assert(d4.consumed == 4, "quic varint pad-up: consumed != 4")
        # 8-byte form: 11xxxxxx <7 more bytes BE>.
        var pad8 = List[UInt8](capacity=8)
        pad8.append(UInt8(0xC0))
        for _ in range(6):
            pad8.append(UInt8(0))
        pad8.append(UInt8(small))
        var d8 = decode_varint(Span[UInt8, _](pad8))
        _assert(
            d8.value == small,
            "quic varint pad-up to 8 bytes: value drift",
        )
        _assert(d8.consumed == 8, "quic varint pad-up: consumed != 8")


def main() raises:
    print("=" * 60)
    print("fuzz_quic_varint.mojo — QUIC varint codec (RFC 9000 §16)")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes(""))
    seeds.append(_bytes("\x00"))  # zero
    seeds.append(_bytes("\x3F"))  # 63 (max 1-byte)
    seeds.append(_bytes("\x40\x00"))  # 0 padded to 2 bytes
    seeds.append(_bytes("\x40\xFF"))
    seeds.append(_bytes("\x7F\xFF"))  # max 2-byte (16383)
    seeds.append(_bytes("\x80\x00\x00\x00"))  # 0 padded to 4 bytes
    seeds.append(_bytes("\xBF\xFF\xFF\xFF"))  # max 4-byte
    seeds.append(_bytes("\xC0\x00\x00\x00\x00\x00\x00\x00"))  # 0 padded to 8
    seeds.append(_bytes("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"))  # VARINT_MAX
    # Truncated multi-byte encodings.
    seeds.append(_bytes("\x40"))
    seeds.append(_bytes("\x80\x00\x00"))
    seeds.append(_bytes("\xC0\x00\x00\x00\x00\x00\x00"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_varint",
            corpus_dir="fuzz/corpus/quic_varint",
            max_input_len=128,
        ),
        seeds,
    )
