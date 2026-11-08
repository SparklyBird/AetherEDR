"""HTTPS in front of the web server, standard library only.

waitress speaks plain HTTP only. This listens on the public address with TLS, and passes the decrypted
bytes to waitress, which stays bound to 127.0.0.1 on a private port. Nothing but this front is reachable
from the network.
"""
from __future__ import annotations

import logging
import os
import socket
import ssl
import threading

log = logging.getLogger("aether.tls")


def server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile)
    ctx.set_alpn_protocols(["http/1.1"])    # waitress does not speak HTTP/2
    return ctx


class TlsFront:
    def __init__(self, host: str, port: int, backend_port: int, certfile: str, keyfile: str) -> None:
        self.host, self.port, self.backend_port = host, port, backend_port
        self.ctx = server_context(certfile, keyfile)
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        bind = "127.0.0.1" if self.host in ("localhost", "") else self.host
        family = socket.AF_INET6 if ":" in bind else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, self.port))
        sock.listen(128)
        self.port = sock.getsockname()[1]      # when 0 was asked for
        self._sock = sock
        threading.Thread(target=self._accept_loop, name="aether-tls", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        backend = None
        tls = None
        try:
            conn.settimeout(10)                                  # a client that stalls the handshake is dropped
            tls = self.ctx.wrap_socket(conn, server_side=True)
            tls.settimeout(None)
            tls.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            backend = socket.create_connection(("127.0.0.1", self.backend_port), timeout=5)
            backend.settimeout(None)
        except (ssl.SSLError, OSError) as exc:
            log.debug("tls connection dropped: %s", exc)
            for s in (tls, conn, backend):
                _close(s)
            return
        done = threading.Event()
        threading.Thread(target=_pump, args=(backend, tls, done), daemon=True).start()
        _pump(tls, backend, done)
        done.wait(2)
        for s in (tls, backend):
            _close(s)


def _pump(src: socket.socket, dst: socket.socket, done: threading.Event) -> None:
    """Copy until src ends. When one direction finishes it half-closes the other so the peer sees EOF."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except (OSError, ssl.SSLError, ValueError):
            pass
        done.set()


def _close(s) -> None:
    if s is not None:
        try:
            s.close()
        except OSError:
            pass
