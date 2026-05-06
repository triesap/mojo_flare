"""WebSocket permessage-deflate (RFC 7692) codec demo.

Walks through:

1. Building a client-side ``Sec-WebSocket-Extensions`` offer.
2. Parsing the offer the way a server would.
3. Negotiating the offer -- v0.7 always locks both sides to
   ``no_context_takeover`` so the response value is deterministic.
4. Compressing a plaintext message with the negotiated config.
5. Decompressing it back, with the per-message decompressed-size
   cap (default 16 MiB) enforced.

The actual RSV1-bit dispatch on the WS frame layer is handled
separately by ``WsFrame.encode_with_key`` (the caller sets the
``rsv1`` flag on the frame they queue). This example focuses on
the codec + handshake plumbing because that's what every
implementer needs to wire up first.
"""

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


def main() raises:
    var client_cfg = PermessageDeflateConfig()
    client_cfg.enabled = True
    var offer = build_permessage_deflate_offer(client_cfg)
    print("[1] client offer header:")
    print("    Sec-WebSocket-Extensions:", offer)

    var parsed = parse_extensions(offer)
    print("[2] server parsed", len(parsed), "offer(s); first =", parsed[0].name)

    var server_cfg = PermessageDeflateConfig()
    server_cfg.enabled = True
    var negotiated = negotiate_permessage_deflate(parsed, server_cfg)
    if not negotiated:
        print("[3] server rejected; nothing acceptable")
        return
    var t = negotiated.value().copy()
    var response_hdr = t[0]
    var pmd_cfg = t[1].copy()
    print("[3] server response header:")
    print("    Sec-WebSocket-Extensions:", response_hdr)
    print(
        "    no_context_takeover (client/server):",
        pmd_cfg.client_no_context_takeover,
        "/",
        pmd_cfg.server_no_context_takeover,
    )

    var msg = String(
        '{"type":"chat","user":"alice","text":"hello, permessage-deflate!"}'
    )
    var compressed = compress_message(
        Span[UInt8, _](msg.as_bytes()), DEFAULT_DEFLATE_LEVEL
    )
    print(
        "[4] compressed",
        msg.byte_length(),
        "B plaintext to",
        len(compressed),
        "B (ratio =",
        Float64(len(compressed)) / Float64(msg.byte_length()),
        ")",
    )

    var plaintext = decompress_message(
        Span[UInt8, _](compressed), DEFAULT_MAX_DECOMPRESSED_BYTES
    )
    print("[5] decompressed back to", len(plaintext), "B (cap = 16 MiB)")
    print("    payload:", String(unsafe_from_utf8=Span[UInt8, _](plaintext)))
