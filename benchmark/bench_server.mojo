"""Benchmark server: minimal HTTP handler for wrk throughput testing.

Minimal HTTP handler for wrk throughput testing.
Routes:
  /             -> 200 OK with "Hello, World!" body
  /json         -> 200 OK with JSON body
  /plaintext    -> 200 OK with "Hello, World!" (text/plain)
  *             -> 404 Not Found

Usage:
    pixi run bench-server
    # In another terminal:
    wrk -t1 -c1 -d10s http://localhost:8080/
"""

from flare.http import HttpServer, Request, Response, Status
from flare.http.server import ServerConfig
from flare.net import SocketAddr


def handler(req: Request) raises -> Response:
    """Minimal TechEmpower-style router for benchmarking."""
    if req.url == "/" or req.url == "/plaintext":
        var body_str = "Hello, World!"
        var body = List[UInt8](capacity=body_str.byte_length())
        for b in body_str.as_bytes():
            body.append(b)
        var resp = Response(status=Status.OK, reason="OK", body=body^)
        resp.headers.set("Content-Type", "text/plain")
        return resp^

    if req.url == "/json":
        var body_str = '{"message":"Hello, World!"}'
        var body = List[UInt8](capacity=body_str.byte_length())
        for b in body_str.as_bytes():
            body.append(b)
        var resp = Response(status=Status.OK, reason="OK", body=body^)
        resp.headers.set("Content-Type", "application/json")
        return resp^

    var body_str = "Not Found"
    var body = List[UInt8](capacity=body_str.byte_length())
    for b in body_str.as_bytes():
        body.append(b)
    return Response(status=Status.NOT_FOUND, reason="Not Found", body=body^)


def main() raises:
    var config = ServerConfig(
        read_buffer_size=8192,
        keep_alive=True,
        max_keepalive_requests=100,
        idle_timeout_ms=0,
        write_timeout_ms=0,
    )
    var srv = HttpServer.bind(SocketAddr.localhost(9090), config^)
    print("flare benchmark server listening on http://localhost:8080")
    print("  Routes: /, /json, /plaintext")
    print("  Keep-alive: enabled (max 100 requests, no timeouts)")
    print("  Buffer size: 8192 bytes")
    print()
    print("Run benchmark with:")
    print("  wrk -t1 -c1 -d10s http://localhost:8080/")
    print("  wrk -t4 -c100 -d10s http://localhost:8080/")
    print()
    srv.serve(handler)
