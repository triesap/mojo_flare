"""HTTP/2 client example: cleartext h2c via the unified ``HttpClient``.

Spawns a child running :class:`flare.http.HttpServer` and a parent
that uses :class:`flare.http.HttpClient` with the
``prefer_h2c=True`` flag to force HTTP/2 cleartext via prior
knowledge (RFC 9113 §3.4 -- the client sends the connection
preface immediately, no ``Upgrade`` dance).

The whole point of the unified surface is that there is no
separate ``Http2Client`` type to learn: the same
``HttpClient.get(url)`` that talks HTTP/1.1 over plain TCP also
talks HTTP/2 cleartext when you opt in via ``prefer_h2c=True``,
and auto-negotiates HTTP/2 vs HTTP/1.1 via TLS+ALPN when the
URL is ``https://`` (no flag needed).

For the TLS (ALPN h2) variant, just swap ``http://`` for
``https://`` -- ``HttpClient`` advertises ALPN
``["h2", "http/1.1"]`` automatically; if the server picks ``h2``
the request is driven through the internal HTTP/2 machinery, if
it picks ``http/1.1`` (or doesn't negotiate ALPN at all) the
existing HTTP/1.1 wire is used. Either way the call site is the
same and the returned :class:`flare.http.Response` is the same.

Run with::

    pixi run -e dev mojo -I . examples/40_http2_client.mojo
"""


from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.net import SocketAddr
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


def _hello(req: Request) raises -> Response:
    return ok('{"hello":"h2"}')


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    print("[h2c server] listening on 127.0.0.1:" + String(Int(port)))

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(150000)

    var base = String("http://127.0.0.1:") + String(Int(port))
    print("[h2c client] connecting to " + base)
    with HttpClient(prefer_h2c=True, base_url=base) as c:
        var r1 = c.get("/api/users")
        print(
            "[h2c] GET /api/users  ->  " + String(r1.status) + " " + r1.text()
        )
        var r2 = c.post("/api/items", '{"name":"flare"}')
        print(
            "[h2c] POST /api/items ->  " + String(r2.status) + " " + r2.text()
        )

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    print("[done]")
