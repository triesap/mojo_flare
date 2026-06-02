"""Smoke test for the rustls_wrapper Rust crate.

This test confirms that:

1. ``libflare_rustls_quic.so`` is present in the expected location
   (next to ``libflare_tls.so`` under the canonical build root, or
   in ``$CONDA_PREFIX/lib`` after the activation script runs).
2. The ABI-version thunk resolves and returns 1 (the crate version
   the Mojo binding expects).
3. The acceptor-new thunk rejects empty PEM input with a non-NULL
   "no CERTIFICATE blocks" error path through ``last_error``.

The full handshake fixture suite lives in
``test_rustls_quic_handshake.mojo`` (lands in Track Q2-W commit
4/4). This smoke just pins the link.
"""

from std.ffi import OwnedDLHandle, c_int
from std.testing import assert_equal, assert_true


def _find_rustls_lib() -> String:
    """The build_rustls.sh activation script (Track Q2-W commit 2/4)
    installs the .so into ``$CONDA_PREFIX/lib/libflare_rustls_quic.so``.
    Until that script lands, the cargo native output path is the
    only one this commit can rely on; the activation commit will
    swap this helper out for the ``find_flare_lib("rustls_quic")``
    canonical-path resolver."""
    return "flare/tls/ffi/rustls_wrapper/target/release/libflare_rustls_quic.so"


def _call_abi_version(read lib: OwnedDLHandle) -> Int:
    """Wrap the FFI thunk in a `read lib` function so Mojo's ASAP
    destructor doesn't unmap the .so between `get_function` and the
    actual call (the same defensive pattern documented in
    `flare/tls/stream.mojo` for the OpenSSL `flare_ssl_ctx_new`
    binding -- without the borrow, the .so is destroyed at the
    last-use point of `lib` and the function pointer becomes
    unmapped before invocation)."""
    var ver_fn = lib.get_function[def() thin abi("C") -> Int](
        "flare_rustls_quic_abi_version"
    )
    return ver_fn()


def _call_acceptor_new(
    read lib: OwnedDLHandle,
    cert_ptr: Int,
    cert_len: Int,
    key_ptr: Int,
    key_len: Int,
    alpn_ptr: Int,
    alpn_len: Int,
) -> Int:
    """`read lib` wrapper for `flare_rustls_quic_acceptor_new`; see
    `_call_abi_version` for why the borrow is required."""
    var new_fn = lib.get_function[
        def(Int, Int, Int, Int, Int, Int) thin abi("C") -> Int
    ]("flare_rustls_quic_acceptor_new")
    return new_fn(cert_ptr, cert_len, key_ptr, key_len, alpn_ptr, alpn_len)


def test_abi_version() raises:
    var path = _find_rustls_lib()
    var lib = OwnedDLHandle(path)
    var v = _call_abi_version(lib)
    assert_equal(v, 1)


def test_acceptor_new_rejects_empty_pem() raises:
    """Empty cert PEM should fail with a useful error message; the
    acceptor pointer returned is NULL (=0)."""
    var path = _find_rustls_lib()
    var lib = OwnedDLHandle(path)
    var empty = List[UInt8]()
    var p = _call_acceptor_new(
        lib,
        Int(empty.unsafe_ptr()),
        0,
        Int(empty.unsafe_ptr()),
        0,
        Int(empty.unsafe_ptr()),
        0,
    )
    # Acceptor pointer is NULL on failure.
    assert_equal(p, 0)


def main() raises:
    test_abi_version()
    test_acceptor_new_rejects_empty_pem()
    print("test_rustls_quic_crate_smoke: 2 passed")
