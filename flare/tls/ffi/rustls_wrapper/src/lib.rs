//! C ABI shim around `rustls::quic::ServerConnection`.
//!
//! Exposes the minimal surface the flare QUIC server reactor needs:
//!
//! - Acceptor lifecycle:
//!   `flare_rustls_quic_acceptor_new` / `_free`
//!   (build an `Arc<ServerConfig>` from PEM cert + key + ALPN list).
//! - Per-connection session:
//!   `flare_rustls_quic_accept`
//!   (constructs a fresh `rustls::quic::ServerConnection` for a DCID).
//! - Drive the handshake:
//!   `flare_rustls_quic_feed_crypto` (write peer's CRYPTO bytes)
//!   `flare_rustls_quic_take_crypto` (drain our outbound CRYPTO bytes)
//!   `flare_rustls_quic_is_handshake_complete`.
//! - Introspect:
//!   `flare_rustls_quic_alpn` (negotiated ALPN id).
//!
//! Every fallible function returns ``int``:
//!
//! - 0 -- success
//! - -1 -- caller-error (bad pointer, bad arg, length-too-small)
//! - -2 -- rustls protocol-level error (sets thread-local message)
//! - -3 -- internal Rust error (sets thread-local message)
//!
//! The thread-local message is fetched via
//! `flare_rustls_quic_last_error`.  Mojo's `OwnedDLHandle` keeps the
//! .so live across the FFI call, so the returned C string is safe to
//! read inside the same invocation.  No cross-thread sharing of the
//! pointer.
//!
//! The crate is `panic = "abort"` because the rustls APIs we use are
//! infallible-or-`Result` already; a panic would mean a rustls
//! internal bug and we want a hard fail (not UB) in that case.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void, CString};
use std::io::Read;
use std::slice;
use std::sync::Arc;

use rustls::quic::{Connection as QuicConnection, KeyChange, Version};
use rustls::server::{ServerConfig, ServerConnection};

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(msg: impl Into<String>) {
    let m = msg.into();
    let c = CString::new(m).unwrap_or_else(|_| {
        CString::new("flare_rustls_quic: error message contains NUL").unwrap()
    });
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(c);
    });
}

/// Returned pointer is valid until the next FFI call on the same
/// thread that sets a different message (or until thread exit).
/// Returns `b"\0"` when no message is recorded.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| {
        let borrow = cell.borrow();
        match borrow.as_ref() {
            Some(c) => c.as_ptr(),
            None => b"\0".as_ptr() as *const c_char,
        }
    })
}

/// Acceptor: long-lived, holds the rustls `ServerConfig`.
pub struct Acceptor {
    config: Arc<ServerConfig>,
}

/// Session: one per QUIC connection. Wraps a
/// `rustls::quic::Connection` (server variant).
pub struct Session {
    conn: QuicConnection,
    /// Pending outbound CRYPTO bytes by encryption level
    /// (0=Initial, 1=EarlyData, 2=Handshake, 3=Application).
    /// rustls coalesces the outbound bytes by level internally;
    /// we just buffer what `write_hs` produces until the Mojo
    /// side calls `take_crypto`.
    pending: [Vec<u8>; 4],
}

/// `flare_rustls_quic_acceptor_new` parses the PEM cert + key,
/// builds a `ServerConfig`, and returns a Box-leaked Acceptor.
///
/// `alpn_protos` is the wire-format ALPN list:
/// `len_byte || proto_bytes || len_byte || proto_bytes || ...`
/// matching the OpenSSL `flare_ssl_ctx_set_alpn_server` thunk's
/// shape so the Mojo side has one ALPN-encoding helper across
/// both backends.
///
/// Returns NULL on construction failure; check
/// `flare_rustls_quic_last_error` for the reason.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_acceptor_new(
    cert_pem: *const u8,
    cert_len: usize,
    key_pem: *const u8,
    key_len: usize,
    alpn_protos: *const u8,
    alpn_len: usize,
) -> *mut c_void {
    if cert_pem.is_null() || key_pem.is_null() {
        set_last_error("flare_rustls_quic_acceptor_new: NULL cert or key");
        return std::ptr::null_mut();
    }
    let cert_bytes = unsafe { slice::from_raw_parts(cert_pem, cert_len) };
    let key_bytes = unsafe { slice::from_raw_parts(key_pem, key_len) };
    let alpn_bytes = if alpn_protos.is_null() || alpn_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(alpn_protos, alpn_len) }
    };

    let certs = match rustls_pemfile::certs(&mut std::io::Cursor::new(cert_bytes))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(certs) if !certs.is_empty() => certs,
        Ok(_) => {
            set_last_error("flare_rustls_quic_acceptor_new: cert PEM contained no CERTIFICATE blocks");
            return std::ptr::null_mut();
        }
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_acceptor_new: cert PEM parse failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    };

    let key = match rustls_pemfile::private_key(&mut std::io::Cursor::new(key_bytes)) {
        Ok(Some(k)) => k,
        Ok(None) => {
            set_last_error("flare_rustls_quic_acceptor_new: key PEM contained no PRIVATE KEY blocks");
            return std::ptr::null_mut();
        }
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_acceptor_new: key PEM parse failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|b| {
            Ok(b.with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| rustls::Error::General(format!("cert/key load: {e}")))?)
        });
    let mut server_config = match builder {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_acceptor_new: ServerConfig build failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    };

    // Parse the wire-format ALPN list into Vec<Vec<u8>>.
    let mut alpn_list = Vec::new();
    let mut i = 0;
    while i < alpn_bytes.len() {
        let len = alpn_bytes[i] as usize;
        i += 1;
        if i + len > alpn_bytes.len() {
            set_last_error("flare_rustls_quic_acceptor_new: ALPN wire format truncated");
            return std::ptr::null_mut();
        }
        alpn_list.push(alpn_bytes[i..i + len].to_vec());
        i += len;
    }
    server_config.alpn_protocols = alpn_list;

    let acceptor = Box::new(Acceptor {
        config: Arc::new(server_config),
    });
    Box::into_raw(acceptor) as *mut c_void
}

/// Free an acceptor returned by `flare_rustls_quic_acceptor_new`.
///
/// NULL is a no-op (safe to call on `_new` returning NULL).
#[no_mangle]
pub extern "C" fn flare_rustls_quic_acceptor_free(acceptor: *mut c_void) {
    if acceptor.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(acceptor as *mut Acceptor);
    }
}

/// Construct a per-connection session.
///
/// `transport_params` is the QUIC transport-parameters extension
/// the server advertises to the peer (RFC 9000 §7.4 + RFC 9001
/// §8.2 -- carried in the TLS ClientHello / EncryptedExtensions
/// `quic_transport_parameters` extension).  Mojo encodes the
/// parameters using `flare.quic.transport_params` and passes the
/// resulting blob here.
///
/// Returns NULL on construction failure.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_accept(
    acceptor: *mut c_void,
    transport_params: *const u8,
    transport_params_len: usize,
) -> *mut c_void {
    if acceptor.is_null() {
        set_last_error("flare_rustls_quic_accept: NULL acceptor");
        return std::ptr::null_mut();
    }
    let acceptor_ref = unsafe { &*(acceptor as *const Acceptor) };
    let tp = if transport_params.is_null() || transport_params_len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(transport_params, transport_params_len).to_vec() }
    };
    let inner = match ServerConnection::new(acceptor_ref.config.clone()) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!(
                "flare_rustls_quic_accept: ServerConnection::new failed: {e}"
            ));
            return std::ptr::null_mut();
        }
    };
    let quic_conn =
        match rustls::quic::ServerConnection::new(acceptor_ref.config.clone(), Version::V1, tp) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(format!(
                    "flare_rustls_quic_accept: rustls::quic::ServerConnection::new failed: {e}"
                ));
                drop(inner);
                return std::ptr::null_mut();
            }
        };
    drop(inner);
    let session = Box::new(Session {
        conn: QuicConnection::Server(quic_conn),
        pending: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
    });
    Box::into_raw(session) as *mut c_void
}

/// Free a session returned by `flare_rustls_quic_accept`.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_session_free(session: *mut c_void) {
    if session.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(session as *mut Session);
    }
}

/// Feed inbound CRYPTO frame bytes at the given encryption level.
///
/// rustls's QUIC API takes the level implicitly -- the level is
/// inferred from the connection's current expected level. We
/// accept the level argument anyway so the Mojo side can pin the
/// dispatch shape (and so a future rustls revision that takes the
/// level explicitly is a one-line change).
///
/// Returns 0 on success, -1 on bad pointer, -2 on rustls error.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_feed_crypto(
    session: *mut c_void,
    _level: c_int,
    buf: *const u8,
    len: usize,
) -> c_int {
    if session.is_null() {
        set_last_error("flare_rustls_quic_feed_crypto: NULL session");
        return -1;
    }
    if buf.is_null() && len > 0 {
        set_last_error("flare_rustls_quic_feed_crypto: NULL buf with non-zero len");
        return -1;
    }
    let sess = unsafe { &mut *(session as *mut Session) };
    let data = unsafe { slice::from_raw_parts(buf, len) };
    let mut cursor = std::io::Cursor::new(data);
    let mut conn_bytes: Vec<u8> = Vec::new();
    if let Err(e) = cursor.read_to_end(&mut conn_bytes) {
        set_last_error(format!("flare_rustls_quic_feed_crypto: read failed: {e}"));
        return -2;
    }
    if let Err(e) = sess.conn.read_hs(&conn_bytes) {
        set_last_error(format!("flare_rustls_quic_feed_crypto: read_hs failed: {e}"));
        return -2;
    }
    // After consuming peer's bytes, pull our outbound bytes into
    // the per-level pending vec. rustls's write_hs returns the
    // current keys + writes to the supplied buffer; we route the
    // bytes into our per-level queue based on rustls's reported
    // level (the connection tracks it internally).
    drain_outbound(sess);
    0
}

/// Drain pending outbound CRYPTO frame bytes at the given level.
///
/// Returns 0 on success; -1 on bad pointer / out_cap too small.
/// On success, `*written` receives the byte count copied into
/// `out`.  When `out_cap` is smaller than the pending bytes the
/// excess stays pending; the Mojo side calls again with a bigger
/// buffer or after sending the previous batch.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_take_crypto(
    session: *mut c_void,
    level: c_int,
    out: *mut u8,
    out_cap: usize,
    written: *mut usize,
) -> c_int {
    if session.is_null() || written.is_null() {
        set_last_error("flare_rustls_quic_take_crypto: NULL session or written");
        return -1;
    }
    if (level as usize) >= 4 {
        set_last_error("flare_rustls_quic_take_crypto: level >= 4");
        return -1;
    }
    let sess = unsafe { &mut *(session as *mut Session) };
    drain_outbound(sess);
    let pending = &mut sess.pending[level as usize];
    let n = pending.len().min(out_cap);
    if n > 0 {
        if out.is_null() {
            set_last_error("flare_rustls_quic_take_crypto: NULL out with non-zero pending");
            return -1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(pending.as_ptr(), out, n);
        }
        pending.drain(..n);
    }
    unsafe { *written = n };
    0
}

/// Whether the handshake has completed (1-RTT keys derived).
///
/// Returns 1 if complete, 0 if not, -1 on bad pointer.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_is_handshake_complete(session: *mut c_void) -> c_int {
    if session.is_null() {
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    // rustls::CommonState::is_handshaking is true while still in
    // the handshake; we flip the boolean.
    let common = match &sess.conn {
        QuicConnection::Server(c) => c.is_handshaking(),
        QuicConnection::Client(c) => c.is_handshaking(),
    };
    if common {
        0
    } else {
        1
    }
}

/// Copy the negotiated ALPN identifier into `out` (no trailing NUL).
///
/// Returns the byte count written, 0 if no ALPN was negotiated,
/// or -1 on bad pointer / out_cap too small.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_alpn(
    session: *mut c_void,
    out: *mut u8,
    out_cap: usize,
    written: *mut usize,
) -> c_int {
    if session.is_null() || written.is_null() {
        set_last_error("flare_rustls_quic_alpn: NULL session or written");
        return -1;
    }
    let sess = unsafe { &*(session as *const Session) };
    let alpn = match &sess.conn {
        QuicConnection::Server(c) => c.alpn_protocol(),
        QuicConnection::Client(c) => c.alpn_protocol(),
    };
    let bytes = match alpn {
        Some(b) => b,
        None => {
            unsafe { *written = 0 };
            return 0;
        }
    };
    if bytes.len() > out_cap {
        set_last_error("flare_rustls_quic_alpn: out_cap too small for ALPN id");
        return -1;
    }
    if !out.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
            *written = bytes.len();
        }
    } else {
        unsafe { *written = bytes.len() };
    }
    bytes.len() as c_int
}

/// Crate version sanity-check thunk so Mojo callers can confirm
/// the .so dlopen resolved to this crate (not a stale build).
/// Returns 1 for v0.1 of the wrapper API; future ABI breaks bump
/// this and force the activation script to rebuild.
///
/// Returns `i64` rather than `c_int` because Mojo callers bind
/// every flare FFI no-arg thunk via `def() thin abi("C") -> Int`,
/// and `Int` is 64-bit. Returning `c_int` would leave the upper
/// 32 bits of `rax` undefined under the SysV x86-64 ABI; the i64
/// shape is the lossless path. The other thunks return `c_int`
/// for parity with the rustls / C-string API and Mojo callers
/// declare them as `c_int` on the Mojo side.
#[no_mangle]
pub extern "C" fn flare_rustls_quic_abi_version() -> i64 {
    1
}

// ── Internal helpers ─────────────────────────────────────────────

/// Pull rustls's outbound CRYPTO bytes into our per-level pending
/// queue.  rustls's `write_hs` API writes to a single Vec and we
/// associate each byte run with the level reported by the
/// returned KeyChange (or the connection's current send level).
///
/// For Track Q2-W commit 1/4 we route every outbound byte into
/// the level the connection is currently emitting; commit 3/4
/// adds the per-level split based on the rustls KeyChange enum.
fn drain_outbound(sess: &mut Session) {
    let mut buf: Vec<u8> = Vec::new();
    let _maybe_keys: Option<KeyChange> = sess.conn.write_hs(&mut buf);
    if buf.is_empty() {
        return;
    }
    // Initial vs Handshake vs 1-RTT: choose by handshake progress.
    // While is_handshaking is true and we have NOT yet derived the
    // handshake keys, the bytes are at Initial level. After the
    // server has produced the ServerHello, rustls returns a
    // KeyChange::Handshake; we use the maybe_keys above to inform
    // the level split, but for commit 1/4 we route everything to
    // the current_level helper below.
    let lvl = level_for(sess);
    sess.pending[lvl].extend_from_slice(&buf);
}

/// Current outbound encryption level the session is emitting at,
/// derived from rustls's introspection. The accurate KeyChange
/// pump in commit 3/4 will replace this with per-byte tagging.
fn level_for(sess: &Session) -> usize {
    let handshaking = match &sess.conn {
        QuicConnection::Server(c) => c.is_handshaking(),
        QuicConnection::Client(c) => c.is_handshaking(),
    };
    if handshaking {
        // We don't yet have a precise level peek; the QUIC server
        // reactor reads INITIAL first, then HANDSHAKE, then 1-RTT.
        // Commit 3/4 wires the KeyChange split so each byte run
        // lands at the correct level.
        0
    } else {
        3
    }
}

// ── In-crate unit tests (cargo test + cargo miri test) ──────────────
//
// These tests exercise the C ABI surface from inside Rust so
// `cargo +nightly miri test` can interpret them under the strict
// undefined-behavior detector.  Miri cannot drive rustls's `ring`
// crypto path (assembly + FFI), so the tests are scoped to:
//
// - acceptor_new with invalid PEM (pure-Rust pemfile parsing)
// - acceptor_free with NULL (no-op safety)
// - last_error round-trip across set / get
// - acceptor_free of a real Box-leaked acceptor (so the Drop
//   chain runs under miri)
//
// The full handshake-driving tests live on the Mojo side under
// `tests/tls/test_rustls_quic_handshake.mojo` (ASan-clean).
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn acceptor_new_rejects_empty_pem() {
        let p = flare_rustls_quic_acceptor_new(
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
        );
        assert!(p.is_null(), "NULL cert should be rejected");
        let err = unsafe { CStr::from_ptr(flare_rustls_quic_last_error()) };
        assert!(
            err.to_string_lossy().contains("NULL cert"),
            "expected NULL-cert error, got {:?}",
            err
        );
    }

    #[test]
    fn acceptor_new_rejects_garbage_pem() {
        let garbage = b"not actually pem";
        let p = flare_rustls_quic_acceptor_new(
            garbage.as_ptr(),
            garbage.len(),
            garbage.as_ptr(),
            garbage.len(),
            std::ptr::null(),
            0,
        );
        assert!(p.is_null(), "garbage PEM should be rejected");
        let err = unsafe { CStr::from_ptr(flare_rustls_quic_last_error()) };
        let msg = err.to_string_lossy();
        assert!(
            msg.contains("CERTIFICATE") || msg.contains("PEM"),
            "expected PEM-parse error, got {:?}",
            msg
        );
    }

    #[test]
    fn acceptor_free_null_is_noop() {
        flare_rustls_quic_acceptor_free(std::ptr::null_mut());
    }

    #[test]
    fn session_free_null_is_noop() {
        flare_rustls_quic_session_free(std::ptr::null_mut());
    }

    #[test]
    fn abi_version_returns_one() {
        assert_eq!(flare_rustls_quic_abi_version(), 1);
    }

    #[test]
    fn last_error_default_is_empty() {
        // Force a fresh thread-local so prior tests don't seed it.
        std::thread::spawn(|| {
            let p = flare_rustls_quic_last_error();
            let c = unsafe { CStr::from_ptr(p) };
            assert_eq!(c.to_bytes(), b"");
        })
        .join()
        .unwrap();
    }

    #[test]
    fn set_last_error_round_trip() {
        set_last_error("test message");
        let p = flare_rustls_quic_last_error();
        let c = unsafe { CStr::from_ptr(p) };
        assert_eq!(c.to_bytes(), b"test message");
    }
}
