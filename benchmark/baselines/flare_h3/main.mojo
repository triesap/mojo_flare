"""Flare HTTP/3 plaintext baseline binary for the bench_h3 harness.

Per Track Q13-W (v0.8 continuation): the bench baseline now
goes through :meth:`flare.http.HttpServer.bind_with_h3` +
:meth:`HttpServer.serve_h3` so the same Handler dispatch shape
production callers use drives the bench workload. The handler
returns a 13-byte ``"Hello, World!"`` body on every request,
matching the existing ``/plaintext`` route the bench harness
expects.

Honest status of the wire (v0.8 continuation, post Q12-W):

The QUIC reactor accepts datagrams, decrypts Initial packets,
feeds the rustls handshake, and drains outbound CRYPTO bytes
back onto the wire (Q9-W .. Q11-W). The H3 dispatch wire is
attached + the Handler is invoked once a request stream surfaces
(Q12-W). The remaining gap is the *rustls KeyChange -> per-level
traffic secrets -> 1-RTT egress* chain: rustls's QUIC API
returns ``Option<KeyChange>`` from ``write_hs`` but the FFI
wrapper currently discards it (see
``flare/tls/ffi/rustls_wrapper/src/lib.rs:447`` for the
``let _maybe_keys = ...`` site). Without per-level traffic
secrets, the Handshake + 1-RTT branches in
:meth:`QuicConnection.handle_packet` drop their inbound
datagrams silently (the Q10-W safety gate) and the egress side
has no key to protect a 1-RTT short-header packet with.

What that means for the bench harness:

* The binary binds + accepts a UDP socket cleanly.
* h2load's first Initial datagram is decrypted + fed into rustls.
* rustls produces a ServerHello which is wrapped in a CRYPTO
  frame and emitted as a protected server Initial.
* h2load's Handshake-level reply lands, but the slot's
  Handshake reader_secret stays empty so the packet is silently
  dropped -- h2load eventually times out the connection.

Closing this gap is the Q13-W follow-up (see the design notebook):
either extend the rustls FFI to surface
``KeyChange::Handshake { keys }`` + ``KeyChange::OneRtt { keys }``
to the Mojo side (preferred -- minimal Mojo-side churn) or
mirror the rustls API by deriving 1-RTT keys ourselves once the
TLS handshake completes (more code, no FFI extension required).
The bench gate ``flare_h3 median req/s >= 72,571 (quiche
floor)`` is documented as deferred-to-the-follow-up commit in
``docs/benchmark.md`` per the Track Q14-W docs sweep.

The binary stays runnable today so the harness can verify the
boot-up path + the listener bind + the Handler-mounted serve
loop; the actual request-rate floor lands once the key bridge
is wired.
"""

from std.os import getenv
from std.pathlib import Path

from flare.http import Handler, HttpServer, Request, Response, ok
from flare.net import IpAddr, SocketAddr
from flare.quic import QuicServerConfig
from flare.tls import RustlsQuicConfig


def _load_pem(path: String) raises -> String:
    """Read a UTF-8 PEM blob into a Mojo String.

    The bench fixture lives under
    ``tests/tls/fixtures/rustls-quic-cert/`` (an Ed25519 self-signed
    cert generated once with ``openssl req -x509 -nodes -newkey
    ed25519 -days 36500 -subj /CN=flare-quic-test``). The bench
    baseline reuses it so we don't ship two copies of the same
    fixture.
    """
    return Path(path).read_text()


@fieldwise_init
struct _PlaintextHandler(Copyable, Handler, Movable):
    """13-byte ``"Hello, World!"`` responder -- matches the
    Rust pack's ``/plaintext`` route shape exactly so the bench
    comparison is honest (no asymmetric response sizes).
    """

    def serve(self, req: Request) raises -> Response:
        return ok(String("Hello, World!"))


def main() raises:
    var port_str = getenv("FLARE_BENCH_PORT", "8443")
    var port = Int(port_str)
    var cert_pem = _load_pem(
        String("tests/tls/fixtures/rustls-quic-cert/cert.pem")
    )
    var key_pem = _load_pem(
        String("tests/tls/fixtures/rustls-quic-cert/key.pem")
    )
    var rustls_cfg = RustlsQuicConfig()
    rustls_cfg.cert_chain_pem = cert_pem^
    rustls_cfg.private_key_pem = key_pem^
    rustls_cfg.alpn_protocols = List[String]()
    rustls_cfg.alpn_protocols.append(String("h3"))

    var udp_cfg = QuicServerConfig()
    udp_cfg.host = String("127.0.0.1")
    udp_cfg.port = UInt16(port)
    udp_cfg.rustls_config = rustls_cfg^
    # Bench shape favors throughput; lift the per-connection
    # initial_max_data so the QUIC flow-control window doesn't
    # throttle a high-rate h2load -n large workload. The default
    # is conservative for general use.
    udp_cfg.initial_max_data = UInt64(32 * 1024 * 1024)
    # Idle timeout long enough that h2load's per-connection
    # warmup + 5 measurement runs (10s + 5x30s = 160s) never
    # tickle the idle reaper.
    udp_cfg.max_idle_timeout_ms = UInt64(300_000)

    # bind_with_h3 also opens a TCP listener on tcp_addr for
    # h1 / h2c / h2; we point it at an ephemeral kernel-picked
    # port we never serve on so the bench harness only sees the
    # UDP socket. This keeps the harness's "single-wire
    # comparison" contract intact -- the harness drives h2load
    # on the UDP port only.
    var tcp_addr = SocketAddr(IpAddr.localhost(), UInt16(0))
    var srv = HttpServer.bind_with_h3(tcp_addr, udp_cfg^)
    var handler = _PlaintextHandler()
    print("flare-h3 listening on 127.0.0.1:", port)
    srv.serve_h3[_PlaintextHandler](handler^)
