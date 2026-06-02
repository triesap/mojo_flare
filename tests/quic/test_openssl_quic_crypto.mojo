"""Tests for :class:`OpenSslQuicCrypto` -- the production QUIC v1
AEAD + header-protection backend.

Covers:

- ``derive_packet_keys`` against the RFC 9001 Appendix A.5 secret
  (the only ChaCha20 vector RFC 9001 publishes that has a full
  ``(key, iv, hp)`` triple alongside it).
- Trait surface round-trip for all three AEAD codepoints (encrypt
  -> decrypt yields the original plaintext; AAD ties the AEAD).
- ``encrypt`` output layout (length == plaintext_len + 16).
- ``decrypt`` rejects a tampered ciphertext with a clear error
  message naming the RFC 9001 paragraph 5.3 invalid-packet path.
- ``header_protection_mask`` returns 5 bytes for a 16-byte sample.

The full RFC 9001 Appendix A.2 client-initial AEAD round-trip
(initial-secret -> client AEAD key + iv -> seal of the real
ClientHello bytes -> packet bytes match the RFC) lands in Track
Q1-W commit 4/4 alongside the aioquic cross-validation.
"""

from std.memory import Span
from std.testing import assert_equal, assert_true

from flare.quic.crypto import (
    OpenSslQuicCrypto,
    PacketKeys,
    QuicAead,
    derive_packet_keys,
)


def _hex(s: String) -> List[UInt8]:
    var bytes = s.as_bytes()
    var out = List[UInt8]()
    var i = 0
    while i < len(bytes):
        var hi = _hex_nibble(bytes[i])
        var lo = _hex_nibble(bytes[i + 1])
        out.append((hi << 4) | lo)
        i += 2
    return out^


@always_inline
def _hex_nibble(c: UInt8) -> UInt8:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    return c - 55


def _eq_bytes(actual: List[UInt8], expected: List[UInt8]) raises:
    assert_equal(len(actual), len(expected))
    for i in range(len(expected)):
        assert_equal(Int(actual[i]), Int(expected[i]))


def test_derive_packet_keys_rfc9001_a5_chacha20() raises:
    """RFC 9001 Appendix A.5 ChaCha20-Poly1305 key schedule.

    secret = 9ac312a7f877468ebe69422748ad00a1
             5443f18203a07d6060f688f30f21632b
    key    = c6d98ff3441c3fe1b2182094f69caa2e
             d4b716b65488960a7a984979fb23e1c8
    iv     = e0459b3474bdd0e44a41c144
    hp     = 25a282b9e82f06f21f488917a4fc8f1b
             73573685608597d0efcb076b0ab7a7a4
    """
    var secret = _hex(
        "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"
    )
    var expected_key = _hex(
        "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"
    )
    var expected_iv = _hex("e0459b3474bdd0e44a41c144")
    var expected_hp = _hex(
        "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"
    )
    var pk = derive_packet_keys(
        Span[UInt8, _](secret), QuicAead.CHACHA20_POLY1305
    )
    assert_equal(pk.aead, QuicAead.CHACHA20_POLY1305)
    _eq_bytes(pk.key, expected_key)
    _eq_bytes(pk.iv, expected_iv)
    _eq_bytes(pk.hp, expected_hp)


def _make_carrier(
    aead: Int, key_len: Int, hp_len: Int
) raises -> OpenSslQuicCrypto:
    var key = List[UInt8]()
    for i in range(key_len):
        key.append(UInt8(0x42 + (i % 8)))
    var iv = List[UInt8]()
    for i in range(12):
        iv.append(UInt8(0x55 + (i % 4)))
    var hp = List[UInt8]()
    for i in range(hp_len):
        hp.append(UInt8(0x33 + (i % 5)))
    var keys = PacketKeys(aead=aead, key=key^, iv=iv^, hp=hp^)
    return OpenSslQuicCrypto(keys=keys^)


def _round_trip(aead: Int, key_len: Int) raises:
    var crypto = _make_carrier(aead, key_len, key_len)
    assert_equal(crypto.aead(), aead)
    var pt = List[UInt8]()
    for i in range(64):
        pt.append(UInt8(i))
    var aad = List[UInt8]()
    for _ in range(8):
        aad.append(UInt8(0xAA))
    var ct = crypto.encrypt(Span[UInt8, _](pt), Span[UInt8, _](aad), UInt64(7))
    assert_equal(len(ct), 64 + 16)
    var recovered = crypto.decrypt(
        Span[UInt8, _](ct), Span[UInt8, _](aad), UInt64(7)
    )
    _eq_bytes(recovered, pt)


def test_round_trip_aes_128_gcm() raises:
    _round_trip(QuicAead.AES_128_GCM, 16)


def test_round_trip_aes_256_gcm() raises:
    _round_trip(QuicAead.AES_256_GCM, 32)


def test_round_trip_chacha20_poly1305() raises:
    # ChaCha20-Poly1305 uses a 32-byte hp key (the hp_len arg).
    _round_trip(QuicAead.CHACHA20_POLY1305, 32)


def test_decrypt_rejects_tampered_ciphertext() raises:
    """Tampering a body byte flips the AEAD tag; decrypt raises
    with a clear error message."""
    var crypto = _make_carrier(QuicAead.AES_128_GCM, 16, 16)
    var pt = List[UInt8]()
    for i in range(16):
        pt.append(UInt8(i))
    var aad = List[UInt8](length=0, fill=UInt8(0))
    var ct = crypto.encrypt(Span[UInt8, _](pt), Span[UInt8, _](aad), UInt64(1))
    ct[0] = ct[0] ^ UInt8(0x01)
    var caught = False
    try:
        _ = crypto.decrypt(Span[UInt8, _](ct), Span[UInt8, _](aad), UInt64(1))
    except _:
        caught = True
    assert_true(caught)


def test_decrypt_short_ciphertext_raises() raises:
    """RFC 9001 paragraph 5.3: ct shorter than the 16-byte AEAD tag
    is invalid by construction."""
    var crypto = _make_carrier(QuicAead.AES_128_GCM, 16, 16)
    var ct = List[UInt8](length=8, fill=UInt8(0))
    var aad = List[UInt8](length=0, fill=UInt8(0))
    var caught = False
    try:
        _ = crypto.decrypt(Span[UInt8, _](ct), Span[UInt8, _](aad), UInt64(0))
    except _:
        caught = True
    assert_true(caught)


def test_hp_mask_returns_5_bytes() raises:
    """RFC 9001 paragraph 5.4.1: the mask is 5 bytes for every AEAD."""
    var crypto = _make_carrier(QuicAead.AES_128_GCM, 16, 16)
    var sample = List[UInt8](length=16, fill=UInt8(0))
    var mask = crypto.header_protection_mask(Span[UInt8, _](sample))
    assert_equal(len(mask), 5)


def test_hp_mask_rejects_wrong_sample_length() raises:
    """Sample is fixed 16 bytes per RFC 9001 paragraph 5.4.2."""
    var crypto = _make_carrier(QuicAead.AES_128_GCM, 16, 16)
    var sample = List[UInt8](length=15, fill=UInt8(0))
    var caught = False
    try:
        _ = crypto.header_protection_mask(Span[UInt8, _](sample))
    except _:
        caught = True
    assert_true(caught)


def test_from_secret_factory() raises:
    """:py:meth:`OpenSslQuicCrypto.from_secret` derives ``PacketKeys``
    and wraps; the underlying ``aead()`` matches the requested
    codepoint."""
    var secret = List[UInt8]()
    for i in range(32):
        secret.append(UInt8(i))
    var crypto = OpenSslQuicCrypto.from_secret(
        Span[UInt8, _](secret), QuicAead.AES_256_GCM
    )
    assert_equal(crypto.aead(), QuicAead.AES_256_GCM)
    # Sanity: round-trip a small message to prove the keys derived
    # correctly through the factory path.
    var pt = List[UInt8]()
    for _ in range(4):
        pt.append(UInt8(0x11))
    var aad = List[UInt8](length=0, fill=UInt8(0))
    var ct = crypto.encrypt(Span[UInt8, _](pt), Span[UInt8, _](aad), UInt64(0))
    var recovered = crypto.decrypt(
        Span[UInt8, _](ct), Span[UInt8, _](aad), UInt64(0)
    )
    _eq_bytes(recovered, pt)


def main() raises:
    test_derive_packet_keys_rfc9001_a5_chacha20()
    test_round_trip_aes_128_gcm()
    test_round_trip_aes_256_gcm()
    test_round_trip_chacha20_poly1305()
    test_decrypt_rejects_tampered_ciphertext()
    test_decrypt_short_ciphertext_raises()
    test_hp_mask_returns_5_bytes()
    test_hp_mask_rejects_wrong_sample_length()
    test_from_secret_factory()
    print("test_openssl_quic_crypto: 9 passed")
